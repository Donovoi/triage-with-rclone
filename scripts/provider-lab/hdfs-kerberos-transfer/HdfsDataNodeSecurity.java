/* Bounded control connections to the synthetic DataNode; never a provider claim. */
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.RealmChoiceCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.hdfs.protocol.BlockChecksumOptions;
import org.apache.hadoop.hdfs.protocol.BlockChecksumType;
import org.apache.hadoop.hdfs.protocol.ExtendedBlock;
import org.apache.hadoop.hdfs.protocol.datatransfer.Sender;
import org.apache.hadoop.hdfs.protocol.proto.DataTransferProtos.BlockOpResponseProto;
import org.apache.hadoop.hdfs.protocol.proto.DataTransferProtos.DataTransferEncryptorMessageProto;
import org.apache.hadoop.hdfs.protocol.proto.DataTransferProtos.DataTransferEncryptorMessageProto.DataTransferEncryptorStatus;
import org.apache.hadoop.hdfs.protocol.proto.DataTransferProtos.Status;
import org.apache.hadoop.hdfs.security.token.block.BlockTokenIdentifier;
import org.apache.hadoop.security.token.Token;

public final class HdfsDataNodeSecurity {
    private static final int FRAME = 8192, WRAPPED = 16384, WIRE = 32768;
    private static final String CHECKSUM = "1a89363878a82c5c7beffed1d407834a";
    private static final boolean[] passed = new boolean[3];
    private static boolean attempted, parserChecked;
    private static volatile boolean running;
    private static int connections, closed, participants, disposed, qopCount, protectedFrames;
    private static int bytesRead, bytesWritten;
    private static long deadline;

    private static void need(boolean value) throws IOException {
        if (!value) throw new IOException("datanode_security_control_invalid");
    }
    private static void time() throws IOException { need(System.nanoTime() < deadline); }
    private static final class BoundedInput extends FilterInputStream {
        int used;
        BoundedInput(InputStream input) { super(input); }
        public int read() throws IOException {
            time(); need(used < WIRE); int value = in.read(); time();
            if (value >= 0) { used++; bytesRead++; } return value;
        }
        public int read(byte[] bytes, int offset, int length) throws IOException {
            time(); need(length >= 0 && length <= WIRE - used);
            int count = in.read(bytes, offset, length); time();
            if (count > 0) { used += count; bytesRead += count; } return count;
        }
    }
    private static final class BoundedOutput extends FilterOutputStream {
        int used;
        BoundedOutput(OutputStream output) { super(output); }
        public void write(int value) throws IOException {
            time(); need(used < WIRE); out.write(value); used++; bytesWritten++; time();
        }
        public void write(byte[] bytes, int offset, int length) throws IOException {
            time(); need(length >= 0 && length <= WIRE - used);
            out.write(bytes, offset, length); used += length; bytesWritten += length; time();
        }
    }
    private static int varint(InputStream input) throws IOException {
        int value = 0;
        for (int index = 0; index < 3; index++) {
            int next = input.read(); if (next < 0) throw new EOFException();
            value |= (next & 127) << (7 * index);
            if ((next & 128) == 0) {
                need(value > 0 && value <= FRAME && (index == 0 || value >= (1 << (7 * index))));
                return value;
            }
        }
        throw new IOException("datanode_security_frame_invalid");
    }
    private static byte[] delimited(InputStream input) throws IOException {
        int size = varint(input); byte[] value = input.readNBytes(size);
        need(value.length == size); return value;
    }
    private static byte[] handshake(InputStream input) throws IOException {
        var value = DataTransferEncryptorMessageProto.parseFrom(delimited(input));
        need(value.getUnknownFields().asMap().isEmpty() && value.getStatus() == DataTransferEncryptorStatus.SUCCESS
            && value.hasPayload() && !value.hasMessage() && !value.hasHandshakeSecret()
            && !value.hasAccessTokenError() && value.getCipherOptionCount() == 0
            && value.getPayload().size() <= FRAME);
        return value.getPayload().toByteArray();
    }
    private static void handshake(OutputStream output, byte[] payload) throws IOException {
        need(payload != null && payload.length <= FRAME);
        var value = DataTransferEncryptorMessageProto.newBuilder().setStatus(DataTransferEncryptorStatus.SUCCESS)
            .setPayload(org.apache.hadoop.thirdparty.protobuf.ByteString.copyFrom(payload)).build();
        need(value.getSerializedSize() <= FRAME); value.writeDelimitedTo(output); output.flush();
    }
    private static void response(BlockOpResponseProto value, boolean negative) throws IOException {
        need(value.getUnknownFields().asMap().isEmpty() && !value.hasFirstBadLink()
            && !value.hasMessage() && !value.hasReadOpChecksumInfo() && !value.hasShortCircuitAccessVersion());
        if (negative) {
            need(value.getStatus() == Status.ERROR_ACCESS_TOKEN && !value.hasChecksumResponse());
            return;
        }
        need(value.getStatus() == Status.SUCCESS && value.hasChecksumResponse());
        var checksum = value.getChecksumResponse();
        need(checksum.getUnknownFields().asMap().isEmpty() && checksum.getBytesPerCrc() == 512
            && checksum.getCrcPerBlock() == 8 && checksum.hasCrcType()
            && checksum.getCrcType().name().equals("CHECKSUM_CRC32C")
            && checksum.hasBlockChecksumOptions()
            && checksum.getBlockChecksumOptions().getUnknownFields().asMap().isEmpty()
            && checksum.getBlockChecksumOptions().hasBlockChecksumType()
            && checksum.getBlockChecksumOptions().getBlockChecksumType().name().equals("MD5CRC")
            && checksum.getBlockChecksumOptions().getStripeLength() == 0
            && HexFormat.of().formatHex(checksum.getBlockChecksum().toByteArray()).equals(CHECKSUM));
    }
    private static byte[] protectedResponse(DataInputStream input, SaslClient sasl) throws IOException {
        ByteArrayOutputStream plain = new ByteArrayOutputStream();
        int size = -1, prefix = -1;
        for (int count = 0; count < 16; count++) {
            int length = input.readInt(); need(length > 0 && length <= WRAPPED);
            byte[] wrapped = input.readNBytes(length); need(wrapped.length == length);
            byte[] part = sasl.unwrap(wrapped, 0, wrapped.length);
            need(part != null && part.length > 0 && plain.size() + part.length <= FRAME + 3);
            plain.write(part); Arrays.fill(part, (byte) 0); Arrays.fill(wrapped, (byte) 0);
            protectedFrames++;
            byte[] bytes = plain.toByteArray();
            if (size < 0) {
                var view = new ByteArrayInputStream(bytes);
                try { size = varint(view); prefix = bytes.length - view.available(); }
                catch (EOFException incomplete) { continue; }
            }
            need(bytes.length <= prefix + size);
            if (bytes.length == prefix + size) return Arrays.copyOfRange(bytes, prefix, bytes.length);
        }
        throw new IOException("datanode_security_frame_count");
    }
    private static final class Credentials implements CallbackHandler, AutoCloseable {
        final String user;
        final char[] password;
        final List<PasswordCallback> retained = new ArrayList<>();
        int callbacks;
        Credentials(byte[] identifier, byte[] secret) {
            user = Base64.getEncoder().encodeToString(identifier);
            byte[] encoded = Base64.getEncoder().encode(secret);
            password = new char[encoded.length];
            for (int i = 0; i < encoded.length; i++) password[i] = (char) (encoded[i] & 255);
            Arrays.fill(encoded, (byte) 0);
        }
        public void handle(Callback[] values) throws IOException, UnsupportedCallbackException {
            need(values != null && values.length <= 8 && callbacks + values.length <= 24);
            callbacks += values.length;
            for (Callback value : values) {
                if (value instanceof NameCallback name) name.setName(user);
                else if (value instanceof PasswordCallback secret) {
                    need(retained.size() < 4); secret.setPassword(password); retained.add(secret);
                } else if (value instanceof RealmCallback realm) realm.setText(realm.getDefaultText());
                else if (value instanceof RealmChoiceCallback realm) {
                    need(realm.getChoices().length == 1); realm.setSelectedIndex(0);
                } else throw new UnsupportedCallbackException(value, "unsupported_owned_callback");
            }
        }
        public void close() {
            Arrays.fill(password, '\0');
            for (PasswordCallback callback : retained) callback.clearPassword();
            retained.clear();
        }
    }
    private static void connection(ExtendedBlock block, Token<BlockTokenIdentifier> valid,
                                   Token<BlockTokenIdentifier> operation, int phase) throws Exception {
        time(); need(phase >= 0 && phase < 3 && connections == phase);
        byte[] identifier = valid.getIdentifier().clone(), secret = valid.getPassword().clone();
        SaslClient sasl = null;
        try (Credentials credentials = new Credentials(identifier, secret)) {
            try (SocketChannel channel = SocketChannel.open()) {
                connections++;
                try {
                    var socket = channel.socket();
                    socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}), 19001), 2000);
                    socket.setSoTimeout(2000);
                    need(socket.getInetAddress().getHostAddress().equals("127.0.0.1") && socket.getPort() == 19001);
                    var input = new DataInputStream(new BoundedInput(socket.getInputStream()));
                    var output = new DataOutputStream(new BoundedOutput(socket.getOutputStream()));
                    sasl = Sasl.createSaslClient(new String[]{"DIGEST-MD5"}, credentials.user, "hdfs", "0",
                        Map.of(Sasl.QOP, "auth-conf", Sasl.SERVER_AUTH, "true", Sasl.MAX_BUFFER, "8192"), credentials);
                    need(sasl != null); participants++;
                    need(sasl.getMechanismName().equals("DIGEST-MD5"));
                    output.writeInt(0xDEADBEEF);
                    handshake(output, sasl.hasInitialResponse() ? sasl.evaluateChallenge(new byte[0]) : new byte[0]);
                    byte[] challenge = handshake(input);
                    byte[] answer = sasl.evaluateChallenge(challenge); Arrays.fill(challenge, (byte) 0);
                    handshake(output, answer); Arrays.fill(answer, (byte) 0);
                    challenge = handshake(input);
                    answer = sasl.evaluateChallenge(challenge); Arrays.fill(challenge, (byte) 0);
                    need(answer == null && sasl.isComplete() && "auth-conf".equals(sasl.getNegotiatedProperty(Sasl.QOP)));
                    qopCount++;
                    ByteArrayOutputStream request = new ByteArrayOutputStream();
                    new Sender(new DataOutputStream(request)).blockChecksum(block, operation,
                        new BlockChecksumOptions(BlockChecksumType.MD5CRC));
                    byte[] bytes = request.toByteArray();
                    need(bytes.length > 0 && bytes.length <= FRAME
                        && bytes.length <= Integer.parseInt(String.valueOf(sasl.getNegotiatedProperty(Sasl.RAW_SEND_SIZE))));
                    byte[] wrapped = sasl.wrap(bytes, 0, bytes.length); Arrays.fill(bytes, (byte) 0);
                    need(wrapped.length > 0 && wrapped.length <= WRAPPED);
                    output.writeInt(wrapped.length); output.write(wrapped); output.flush(); Arrays.fill(wrapped, (byte) 0);
                    response(BlockOpResponseProto.parseFrom(protectedResponse(input, sasl)), phase == 1);
                    need(input.read() == -1); time(); passed[phase] = true;
                } finally {
                    try { channel.close(); if (!channel.isOpen()) closed++; }
                    finally { if (sasl != null) { sasl.dispose(); disposed++; } }
                }
            }
        } finally { Arrays.fill(identifier, (byte) 0); Arrays.fill(secret, (byte) 0); }
    }
    public static void run(DistributedFileSystem filesystem, String expectedNode, long until) throws Exception {
        need(!attempted && parserChecked); attempted = true; running = true;
        try { execute(filesystem, expectedNode, until); }
        finally { running = false; }
        need(complete() && clean());
    }
    private static void execute(DistributedFileSystem filesystem, String expectedNode, long until) throws Exception {
        deadline = until; time();
        var located = filesystem.getClient().getLocatedBlocks("/synthetic/nested/space name.bin", 0, 4096);
        need(located != null && located.getFileLength() == 4096 && !located.isUnderConstruction()
            && located.getLocatedBlocks().size() == 1);
        var entry = located.getLocatedBlocks().get(0);
        need(!entry.isCorrupt() && entry.getStartOffset() == 0 && entry.getBlockSize() == 4096
            && entry.getLocations().length == 1 && entry.getLocations()[0].getDatanodeUuid().equals(expectedNode)
            && entry.getLocations()[0].getIpAddr().equals("127.0.0.1") && entry.getLocations()[0].getXferPort() == 19001);
        var token = entry.getBlockToken();
        need(token != null && token.getKind().toString().equals("HDFS_BLOCK_TOKEN")
            && token.getIdentifier().length > 0 && token.getIdentifier().length <= 4096
            && token.getPassword().length >= 16 && token.getPassword().length <= 64);
        var decoded = token.decodeIdentifier();
        need(decoded != null && (decoded.getHandshakeMsg() == null || decoded.getHandshakeMsg().length == 0));
        byte[] wrong = token.getPassword().clone(); wrong[0] ^= 1;
        var invalid = new Token<BlockTokenIdentifier>(token.getIdentifier().clone(), wrong, token.getKind(), token.getService());
        try {
            connection(entry.getBlock(), token, token, 0);
            connection(entry.getBlock(), token, invalid, 1);
            connection(entry.getBlock(), token, token, 2);
        } finally { Arrays.fill(wrong, (byte) 0); }
    }
    public static boolean complete() {
        return !running && attempted && parserChecked && connections == 3 && participants == 3 && qopCount == 3
            && passed[0] && passed[1] && passed[2] && protectedFrames >= 3 && protectedFrames <= 48;
    }
    public static boolean clean() { return !running && connections == closed && participants == disposed; }
    public static String json() {
        return "{\"attempted\":" + attempted + ",\"parser_checked\":" + parserChecked
            + ",\"quiescent\":" + !running
            + ",\"connections\":" + connections + ",\"closed\":" + closed
            + ",\"participants\":" + participants + ",\"disposed\":" + disposed
            + ",\"qop_observations\":" + qopCount + ",\"protected_frames\":" + protectedFrames
            + ",\"wire_bytes_read\":" + bytesRead + ",\"wire_bytes_written\":" + bytesWritten
            + ",\"qop\":\"" + (qopCount > 0 ? "auth-conf" : "not_observed") + "\""
            + ",\"valid_before\":" + passed[0] + ",\"invalid_operation_token\":" + passed[1]
            + ",\"valid_after\":" + passed[2] + ",\"rclone_qop_verified\":false}";
    }
    public static void selfCheck() throws Exception {
        need(!parserChecked && !attempted);
        byte[][] invalid = {{}, {0}, {(byte)128}, {(byte)128,0}, {(byte)129,0},
            {(byte)255,(byte)255,127}, {(byte)128,(byte)128,(byte)128}, {2,8}};
        for (byte[] bytes : invalid) {
            boolean rejected = false;
            try { delimited(new ByteArrayInputStream(bytes)); } catch (IOException expected) { rejected = true; }
            need(rejected);
        }
        need(Arrays.equals(delimited(new ByteArrayInputStream(new byte[]{2,8,5})), new byte[]{8,5}));
        response(BlockOpResponseProto.newBuilder().setStatus(Status.ERROR_ACCESS_TOKEN).build(), true);
        for (Status status : List.of(Status.SUCCESS, Status.ERROR, Status.ERROR_CHECKSUM, Status.ERROR_INVALID)) {
            boolean rejected = false;
            try { response(BlockOpResponseProto.newBuilder().setStatus(status).build(), true); }
            catch (IOException expected) { rejected = true; }
            need(rejected);
        }
        parserChecked = true;
    }
}
