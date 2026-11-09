import java.util.*;
import org.apache.hadoop.ipc.protobuf.RpcHeaderProtos.RpcRequestHeaderProto;
import org.apache.hadoop.ipc.protobuf.RpcHeaderProtos.RpcResponseHeaderProto;
import org.apache.hadoop.ipc.protobuf.RpcHeaderProtos.RpcSaslProto;

/** Observes one owned HDFS connection without changing or retaining wire bytes. */
final class HdfsRenewalSaslGate implements AutoCloseable {
    static final class Rejected extends Exception { Rejected(){super("sasl_binding_rejected");} }
    static void need(boolean ok) throws Rejected {if(!ok)throw new Rejected();}
    final MitRenewalEvidence evidence;final boolean fresh;
    final Map<Integer,HdfsRenewalRpcGate.Request> pending=new LinkedHashMap<>();
    byte[] clientId;
    String stage="start";
    int clientFrames,serverFrames,contextFrames,listingReplies,listingRequests;
    boolean apBound,authenticated,closed,completeBeforeClose;
    int pendingAtClose;
    HdfsRenewalSaslGate(MitRenewalEvidence evidence,boolean fresh) throws Rejected {
        need(evidence!=null);this.evidence=evidence;this.fresh=fresh;
    }
    private static RpcSaslProto sasl(byte[] bytes) throws Exception {
        RpcSaslProto value=RpcSaslProto.parseFrom(bytes);
        need(value.isInitialized() && value.getUnknownFields().asMap().isEmpty() && Arrays.equals(bytes,value.toByteArray())
            && value.getToken().size()<=65536 && value.getAuthsCount()<=4);
        for(var auth:value.getAuthsList())need(auth.isInitialized() && auth.getUnknownFields().asMap().isEmpty()
            && auth.getMethod().length()<=32 && auth.getMechanism().length()<=32
            && auth.getProtocol().length()<=32 && auth.getServerId().length()<=256 && auth.getChallenge().size()<=4096);
        return value;
    }
    private static boolean kerberos(RpcSaslProto.SaslAuth auth){
        return auth.getMethod().equals("KERBEROS") && auth.getMechanism().equals("GSSAPI")
            && auth.getProtocol().equals("hdfs") && auth.getServerId().equals("127.0.0.1");
    }
    synchronized void client(byte[] frame) throws Exception {
        need(!closed && ++clientFrames<=64);
        HdfsRenewalRpcGate.Request request=HdfsRenewalRpcGate.request(frame);boolean retained=false;
        List<byte[]> parts=HdfsRenewalRpcGate.parts(frame,2,3);
        byte[] current=null;
        try{
            RpcRequestHeaderProto header=RpcRequestHeaderProto.parseFrom(parts.get(0));current=header.getClientId().toByteArray();
            if(clientId==null)clientId=current.clone();else need(Arrays.equals(clientId,current));
            if(request.callId==-33){
                need(parts.size()==2 && !authenticated);RpcSaslProto value=sasl(parts.get(1));
                String state=value.getState().name();
                if(stage.equals("start")){
                    need(state.equals("NEGOTIATE") && value.getToken().isEmpty() && value.getAuthsCount()==0);
                    stage="negotiate_sent";
                }else if(stage.equals("negotiate_received")){
                    need(state.equals("INITIATE") && !value.getToken().isEmpty() && value.getAuthsCount()==1 && kerberos(value.getAuths(0)));
                    byte[] token=value.getToken().toByteArray();
                    try{evidence.verifyMechanismToken(token,fresh);apBound=true;}finally{Arrays.fill(token,(byte)0);}
                    stage="initiate_sent";
                }else if(stage.equals("challenge_received")){
                    need(state.equals("RESPONSE") && !value.getToken().isEmpty() && value.getToken().size()<=4096 && value.getAuthsCount()==0);
                    stage="response_sent";
                }else throw new Rejected();
            }else if(request.callId==-3){
                need(authenticated && apBound && ++contextFrames==1 && parts.size()==2);
            }else{
                need(authenticated && apBound && contextFrames==1 && request.callId>0 && pending.size()<32 && !pending.containsKey(request.callId));
                pending.put(request.callId,request);retained=true;
                if(request.kind==HdfsRenewalRpcGate.Kind.LISTING)listingRequests++;
            }
        }finally{
            HdfsRenewalRpcGate.erase(parts);if(current!=null)Arrays.fill(current,(byte)0);if(!retained)request.close();
        }
    }
    synchronized void server(byte[] frame) throws Exception {
        need(!closed && ++serverFrames<=64);
        int call=HdfsRenewalRpcGate.responseCallId(frame);
        List<byte[]> parts=HdfsRenewalRpcGate.parts(frame,1,2);
        try{
            RpcResponseHeaderProto header=RpcResponseHeaderProto.parseFrom(parts.get(0));
            if(call==-33){
                need(!authenticated && parts.size()==2 && header.getStatus()==RpcResponseHeaderProto.RpcStatusProto.SUCCESS);
                RpcSaslProto value=sasl(parts.get(1));String state=value.getState().name();
                if(stage.equals("negotiate_sent")){
                    need(state.equals("NEGOTIATE") && value.getToken().isEmpty() && value.getAuthsCount()>=1);
                    need(value.getAuthsList().stream().filter(HdfsRenewalSaslGate::kerberos).count()==1);
                    for(var auth:value.getAuthsList())need(kerberos(auth)||auth.getMethod().equals("TOKEN") && auth.getMechanism().equals("DIGEST-MD5"));
                    stage="negotiate_received";
                }else if(stage.equals("initiate_sent")){
                    need(apBound && state.equals("CHALLENGE") && value.getAuthsCount()==0 && !value.getToken().isEmpty() && value.getToken().size()<=4096);
                    stage="challenge_received";
                }else if(stage.equals("response_sent")){
                    need(apBound && state.equals("SUCCESS") && value.getAuthsCount()==0 && value.getToken().isEmpty());
                    authenticated=true;stage="authenticated";
                }else throw new Rejected();
            }else{
                need(authenticated && apBound && call>0);
                HdfsRenewalRpcGate.Request request=pending.remove(call);need(request!=null);
                try{
                    if(request.kind==HdfsRenewalRpcGate.Kind.LISTING){
                        HdfsRenewalRpcGate.matchingEmptyListingResponse(frame,request);listingReplies++;
                    }
                }finally{request.close();}
            }
        }finally{HdfsRenewalRpcGate.erase(parts);}
    }
    synchronized void requireListing() throws Rejected {
        need(authenticated && apBound && contextFrames==1 && listingReplies>=1 && listingReplies==listingRequests && pending.isEmpty());
    }
    synchronized Map<String,Object> projection(){
        Map<String,Object> out=new LinkedHashMap<>();out.put("stage",stage);out.put("fresh_connection",fresh);out.put("client_frames",clientFrames);
        out.put("server_frames",serverFrames);out.put("context_frames",contextFrames);out.put("ap_ticket_bound",apBound);
        out.put("sasl_success",authenticated);out.put("listing_requests",listingRequests);out.put("matching_listing_replies",listingReplies);
        out.put("pending_requests",pending.size());out.put("pending_at_close",pendingAtClose);
        out.put("complete_before_close",completeBeforeClose);out.put("closed",closed);return out;
    }
    @Override public synchronized void close(){
        if(closed)return;
        pendingAtClose=pending.size();completeBeforeClose=authenticated && apBound && contextFrames==1
            && listingReplies>=1 && listingReplies==listingRequests && pending.isEmpty();
        for(var request:pending.values())request.close();pending.clear();if(clientId!=null)Arrays.fill(clientId,(byte)0);closed=true;
    }
}
