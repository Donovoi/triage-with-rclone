import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.hadoop.ipc.protobuf.RpcHeaderProtos.RpcRequestHeaderProto;
import org.apache.hadoop.ipc.protobuf.RpcHeaderProtos.RpcResponseHeaderProto;
import org.apache.hadoop.ipc.protobuf.RpcHeaderProtos.RpcKindProto;
import org.apache.hadoop.ipc.protobuf.ProtobufRpcEngine2Protos.RequestHeaderProto;
import org.apache.hadoop.hdfs.protocol.proto.ClientNamenodeProtocolProtos.GetListingRequestProto;
import org.apache.hadoop.hdfs.protocol.proto.ClientNamenodeProtocolProtos.GetListingResponseProto;

/** Source-stage inspector for the future owned, authentication-only RPC relay.
 * It does not open sockets, hold a response, cancel a job, or grant acceptance.
 * The caller must enforce connection identity, deadlines, byte budgets and erasure
 * of its original frame. This class owns and erases its temporary frame slices.
 */
final class HdfsRenewalRpcGate {
    static final int MAX_FRAME = 65536;
    private static final String PROTOCOL = "org.apache.hadoop.hdfs.protocol.ClientProtocol";
    private static final String TARGET = "/synthetic/empty";
    enum Kind { CONTROL, FILE_INFO, LISTING, LEASE }

    static final class Rejected extends Exception {
        Rejected() { super("rpc_gate_frame_rejected"); }
    }

    static final class Request implements AutoCloseable {
        final int callId;
        final Kind kind;
        private final byte[] clientId;
        private boolean closed;
        private Request(int callId, Kind kind, byte[] clientId) {
            this.callId = callId;
            this.kind = kind;
            this.clientId = clientId;
        }
        @Override public void close() {
            Arrays.fill(clientId, (byte)0);
            closed = true;
        }
    }

    private static void require(boolean value) throws Rejected {
        if (!value) throw new Rejected();
    }

    // Framing is checked before protobuf parsing. Only canonical, bounded
    // unsigned varint lengths are accepted; no length can allocate beyond frame.
    private static int length(DataInputStream input) throws Exception {
        int result = 0;
        for (int shift = 0; shift <= 28; shift += 7) {
            int value = input.readUnsignedByte();
            require(shift != 28 || (value & 0xf0) == 0);
            result |= (value & 0x7f) << shift;
            if ((value & 0x80) == 0) {
                require((shift == 0 || value != 0) && result >= 0 && result <= MAX_FRAME);
                return result;
            }
        }
        throw new Rejected();
    }

    static List<byte[]> parts(byte[] frame, int minimum, int maximum) throws Rejected {
        List<byte[]> parts = new ArrayList<>();
        try {
            require(frame != null && frame.length >= 5 && frame.length <= MAX_FRAME + 4);
            DataInputStream input = new DataInputStream(new ByteArrayInputStream(frame));
            int total = input.readInt();
            require(total > 0 && total <= MAX_FRAME && total == frame.length - 4);
            while (input.available() > 0) {
                require(parts.size() < maximum);
                int size = length(input);
                require(size <= input.available());
                parts.add(input.readNBytes(size));
            }
            require(parts.size() >= minimum);
            return parts;
        } catch (Exception failure) {
            erase(parts);
            throw new Rejected();
        }
    }

    static void erase(List<byte[]> parts) {
        for (byte[] part : parts) Arrays.fill(part, (byte)0);
    }

    static Request request(byte[] frame) throws Rejected {
        List<byte[]> parts = parts(frame, 2, 3);
        byte[] client = null;
        boolean transferred = false;
        try {
            RpcRequestHeaderProto header = RpcRequestHeaderProto.parseFrom(parts.get(0));
            require(header.isInitialized() && header.getUnknownFields().asMap().isEmpty()
                && Arrays.equals(parts.get(0), header.toByteArray()));
            require(header.hasRpcKind() && header.getRpcKind() == RpcKindProto.RPC_PROTOCOL_BUFFER
                && header.hasRpcOp() && header.getRpcOp() == RpcRequestHeaderProto.OperationProto.RPC_FINAL_PACKET);
            // The pinned Go sender emits only these four fields. Optional retry,
            // trace, caller, state or router fields must not enter this fixture.
            require(header.getAllFields().size() == 4 && header.getClientId().size() == 16);
            client = header.getClientId().toByteArray();
            int call = header.getCallId();
            Kind kind;
            if (call < 0) {
                require((call == -3 || call == -33) && parts.size() == 2);
                kind = Kind.CONTROL;
            } else {
                require(call > 0 && parts.size() == 3);
                RequestHeaderProto method = RequestHeaderProto.parseFrom(parts.get(1));
                require(method.isInitialized() && method.getUnknownFields().asMap().isEmpty()
                    && Arrays.equals(parts.get(1), method.toByteArray()));
                require(method.getDeclaringClassProtocolName().equals(PROTOCOL)
                    && method.getClientProtocolVersion() == 1);
                kind = switch (method.getMethodName()) {
                    case "getFileInfo" -> Kind.FILE_INFO;
                    case "getListing" -> Kind.LISTING;
                    case "renewLease" -> Kind.LEASE;
                    default -> throw new Rejected();
                };
                if (kind == Kind.LISTING) {
                    GetListingRequestProto listing = GetListingRequestProto.parseFrom(parts.get(2));
                    require(listing.isInitialized() && listing.getUnknownFields().asMap().isEmpty()
                        && Arrays.equals(parts.get(2), listing.toByteArray()));
                    require(listing.getSrc().equals(TARGET) && listing.getStartAfter().isEmpty()
                        && !listing.getNeedLocation());
                }
            }
            Request result = new Request(call, kind, client);
            transferred = true;
            return result;
        } catch (Exception failure) {
            throw new Rejected();
        } finally {
            erase(parts);
            if (!transferred && client != null) Arrays.fill(client, (byte)0);
        }
    }

    // Header-only errors must remain distinguishable from a holdable success.
    // This accessor does not grant a matching-listing or cancellation witness.
    static int responseCallId(byte[] frame) throws Rejected {
        List<byte[]> parts = parts(frame, 1, 2);
        try {
            RpcResponseHeaderProto header = RpcResponseHeaderProto.parseFrom(parts.get(0));
            require(header.isInitialized() && header.getUnknownFields().asMap().isEmpty()
                && Arrays.equals(parts.get(0), header.toByteArray()));
            int call = header.getCallId();
            require(call > 0 || call == -33 || call == -3);
            require(parts.size() == (header.getStatus() == RpcResponseHeaderProto.RpcStatusProto.SUCCESS ? 2 : 1));
            return call;
        } catch (Exception failure) {
            throw new Rejected();
        } finally { erase(parts); }
    }

    // A complete, successful empty-directory reply for the matched listing is
    // the only hold candidate. A denial, another call or a control frame is not.
    static void matchingEmptyListingResponse(byte[] frame, Request request) throws Rejected {
        require(request != null && !request.closed && request.kind == Kind.LISTING && request.callId > 0);
        List<byte[]> parts = parts(frame, 2, 3);
        byte[] responseClient = null;
        try {
            require(parts.size() == 2);
            RpcResponseHeaderProto header = RpcResponseHeaderProto.parseFrom(parts.get(0));
            require(header.isInitialized() && header.getUnknownFields().asMap().isEmpty()
                && Arrays.equals(parts.get(0), header.toByteArray()));
            require(header.getCallId() == request.callId
                && header.getStatus() == RpcResponseHeaderProto.RpcStatusProto.SUCCESS);
            require(!header.hasExceptionClassName() && !header.hasErrorMsg() && !header.hasErrorDetail()
                && (!header.hasServerIpcVersionNum() || header.getServerIpcVersionNum() == 9)
                && header.getRetryCount() == -1 && header.getStateId() >= 0
                && header.getRouterFederatedState().isEmpty());
            if (header.hasClientId()) {
                responseClient = header.getClientId().toByteArray();
                require(Arrays.equals(responseClient, request.clientId));
            }
            GetListingResponseProto response = GetListingResponseProto.parseFrom(parts.get(1));
            require(response.isInitialized() && response.getUnknownFields().asMap().isEmpty()
                && Arrays.equals(parts.get(1), response.toByteArray()) && response.hasDirList());
            var listing = response.getDirList();
            require(listing.getUnknownFields().asMap().isEmpty() && listing.getPartialListingCount() == 0
                && listing.getRemainingEntries() == 0);
        } catch (Exception failure) {
            throw new Rejected();
        } finally {
            erase(parts);
            if (responseClient != null) Arrays.fill(responseClient, (byte)0);
        }
    }
}
