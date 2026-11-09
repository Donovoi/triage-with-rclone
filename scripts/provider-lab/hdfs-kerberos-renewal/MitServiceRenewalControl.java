/* Contained MIT service-ticket renewal counterfactual. No rclone credit. */
import java.io.*;
import java.net.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import org.apache.kerby.kerberos.kerb.*;
import org.apache.kerby.kerberos.kerb.crypto.*;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.ap.*;
import org.apache.kerby.kerberos.kerb.type.base.*;
import org.apache.kerby.kerberos.kerb.type.kdc.*;
import org.apache.kerby.kerberos.kerb.type.pa.*;
import org.apache.kerby.kerberos.kerb.type.ticket.*;

final class MitServiceRenewalControl {
    static final List<Socket> sockets=new CopyOnWriteArrayList<>();
    static final Map<String,Boolean> checks=new LinkedHashMap<>();
    static {
        for(String key:List.of("expired_original","same_request_binding","wrong_usage_rejected",
                "reply_authenticated","nonce_client_server_bound","renewed_times_bound",
                "fresh_ticket_and_key","reply_controls","sockets_closed")) checks.put(key,false);
    }
    static int exchanges,wrongUsageError,correctUsageError,replyControls,renewedLifetime;
    static String stage="not_started";
    static void need(boolean ok) { if(!ok) throw new IllegalStateException("manual_renewal_predicate_failed"); }
    static void close() {
        for(Socket socket:sockets) try { socket.close(); } catch(IOException ignored) { }
        checks.put("sockets_closed",sockets.stream().allMatch(Socket::isClosed));
    }
    static Map<String,Object> projection() {
        Map<String,Object> out=new LinkedHashMap<>();
        out.put("stage",stage);out.put("checks",new LinkedHashMap<>(checks));
        out.put("exchanges",exchanges);out.put("wrong_usage_error",wrongUsageError);
        out.put("correct_usage_error",correctUsageError);out.put("reply_controls",replyControls);out.put("renewed_lifetime_seconds",renewedLifetime);
        out.put("manual_reply_verified",checks.values().stream().allMatch(Boolean::booleanValue));
        out.put("rclone_renewal_verified",false);
        return out;
    }
    static byte[] exchange(byte[] request) throws Exception {
        need(request.length>2 && request.length<=65536 && sockets.size()<2);
        Socket socket=new Socket();sockets.add(socket);
        try {
            socket.setSoTimeout(3000);
            socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}),18888),2000);
            DataOutputStream out=new DataOutputStream(socket.getOutputStream());
            out.writeInt(request.length);out.write(request);out.flush();exchanges++;
            DataInputStream in=new DataInputStream(socket.getInputStream());
            int length=in.readInt();need(length>2 && length<=65536);
            byte[] reply=in.readNBytes(length);need(reply.length==length);return reply;
        } finally { socket.close(); }
    }
    static byte[] request(KdcReqBody body,Ticket ticket,EncryptedData encrypted,byte[] bodyBytes,byte[] ticketBytes) throws Exception {
        ApReq ap=new ApReq();ap.setApOptions(new ApOptions(0));ap.setTicket(ticket);ap.setEncryptedAuthenticator(encrypted);
        byte[] pa=KrbCodec.encode(ap);
        TgsReq req=new TgsReq();req.setReqBody(body);req.addPaData(new PaDataEntry(PaDataType.TGS_REQ,pa));
        byte[] raw=KrbCodec.encode(req);
        try {
            TgsReq decoded=KrbCodec.decode(raw,TgsReq.class);
            need(decoded.getPvno()==5 && decoded.getMsgType()==KrbMessageType.TGS_REQ
                && Arrays.equals(raw,KrbCodec.encode(decoded))
                && Arrays.equals(bodyBytes,KrbCodec.encode(decoded.getReqBody()))
                && Arrays.equals(ticketBytes,KrbCodec.encode(ap.getTicket())));
            return raw;
        } finally { Arrays.fill(pa,(byte)0); }
    }
    static byte[] decrypt(EncryptedData cipher,EncryptionKey key,KeyUsage usage) throws Exception {
        need(cipher.getEType()==EncryptionType.AES128_CTS_HMAC_SHA1_96
            && cipher.getCipher().length>=28 && cipher.getCipher().length<=65536);
        byte[] copy=cipher.getCipher().clone();
        try { return EncryptionHandler.decrypt(copy,key,usage); }
        catch(KrbException failure) {
            if(failure.getKrbErrorCode()==KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY)return null;
            throw failure;
        } finally { Arrays.fill(copy,(byte)0); }
    }
    static boolean boundPart(EncTgsRepPart part,EncKdcRepPart original,String realm,int nonce,long requestTime) {
        if(part.getFlags()==null || part.getKey()==null || part.getSname()==null
            || part.getAuthTime()==null || part.getStartTime()==null || part.getEndTime()==null || part.getRenewTill()==null)return false;
        long start=part.getStartTime().getTime(),end=part.getEndTime().getTime();
        return part.getNonce()==nonce && realm.equals(part.getSrealm())
            && part.getSname().getNameStrings().equals(List.of("hdfs","127.0.0.1"))
            && part.getAuthTime().getTime()==original.getAuthTime().getTime()
            && start>=original.getEndTime().getTime()+1000 && Math.abs(start-requestTime)<=3000
            && end-start>=8000 && end-start<=10000 && end>original.getEndTime().getTime()
            && part.getRenewTill().getTime()==original.getRenewTill().getTime() && end<=part.getRenewTill().getTime()
            && (part.getFlags().getFlags() & 0x00800000)!=0
            && (part.getFlags().getFlags() & 0x50000000)==0
            && part.getKey().getKeyType()==EncryptionType.AES128_CTS_HMAC_SHA1_96 && part.getKey().getKeyData().length==16;
    }
    static void run(String realm,String reader,SgtTicket issued) throws Exception {
        stage="prepare";
        EncKdcRepPart original=issued.getEncKdcRepPart();
        long now=System.currentTimeMillis();
        need(original.getRenewTill()!=null && now>=original.getEndTime().getTime()+1000
            && now+20000<original.getRenewTill().getTime());
        checks.put("expired_original",true);
        EncryptionKey key=new EncryptionKey(17,issued.getSessionKey().getKeyData().clone());
        byte[] bodyBytes=null,ticketBytes=null,authBytes=null,badRequest=null,goodRequest=null,badReply=null,goodReply=null,plain=null;
        EncTgsRepPart part=null;EncryptedData encryptedBad=null,encryptedGood=null;
        try {
            PrincipalName client=new PrincipalName(reader);
            need(client.getNameStrings().size()==1 && realm.equals(client.getRealm()));
            KdcReqBody body=new KdcReqBody();body.setKdcOptions(new KdcOptions(KdcOption.RENEW.getValue()));
            body.setCname(client);body.setRealm(realm);body.setSname(issued.getTicket().getSname());
            int nonce=new SecureRandom().nextInt(Integer.MAX_VALUE);body.setNonce(nonce);
            body.setTill(new KerberosTime(now+10000));body.setEtypes(List.of(EncryptionType.AES128_CTS_HMAC_SHA1_96));
            bodyBytes=KrbCodec.encode(body);ticketBytes=KrbCodec.encode(issued.getTicket());
            Authenticator auth=new Authenticator();auth.setCrealm(realm);auth.setCname(client);
            auth.setCtime(new KerberosTime((now/1000)*1000));auth.setCusec((int)(now%1000)*1000);
            auth.setCksum(CheckSumHandler.checksumWithKey(CheckSumType.HMAC_SHA1_96_AES128,bodyBytes,key.getKeyData(),KeyUsage.TGS_REQ_AUTH_CKSUM));
            authBytes=KrbCodec.encode(auth);
            encryptedBad=EncryptionHandler.encrypt(authBytes,key,KeyUsage.AP_REQ_AUTH);
            encryptedGood=EncryptionHandler.encrypt(authBytes,key,KeyUsage.TGS_REQ_AUTH);
            badRequest=request(body,issued.getTicket(),encryptedBad,bodyBytes,ticketBytes);
            goodRequest=request(body,issued.getTicket(),encryptedGood,bodyBytes,ticketBytes);
            checks.put("same_request_binding",true);
            stage="wrong_usage";
            badReply=exchange(badRequest);KrbError denial=KrbCodec.decode(badReply,KrbError.class);
            need(denial.getPvno()==5 && denial.getMsgType()==KrbMessageType.KRB_ERROR
                && Arrays.equals(badReply,KrbCodec.encode(denial)) && denial.getErrorCode()!=null);
            wrongUsageError=denial.getErrorCode().getValue();
            need(denial.getErrorCode()==KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY);
            checks.put("wrong_usage_rejected",true);
            stage="correct_usage";
            goodReply=exchange(goodRequest);
            if(Byte.toUnsignedInt(goodReply[0])==0x7e) {
                KrbError rejected=KrbCodec.decode(goodReply,KrbError.class);
                need(rejected.getErrorCode()!=null && Arrays.equals(goodReply,KrbCodec.encode(rejected)));
                correctUsageError=rejected.getErrorCode().getValue();
                throw new KrbException(rejected.getErrorCode());
            }
            TgsRep reply=KrbCodec.decode(goodReply,TgsRep.class);
            need(reply.getPvno()==5 && reply.getMsgType()==KrbMessageType.TGS_REP
                && Arrays.equals(goodReply,KrbCodec.encode(reply)) && reply.getTicket()!=null
                && realm.equals(reply.getCrealm()) && reply.getCname()!=null
                && reply.getCname().getNameStrings().equals(client.getNameStrings())
                && realm.equals(reply.getTicket().getRealm())
                && reply.getTicket().getSname().getNameStrings().equals(List.of("hdfs","127.0.0.1")));
            plain=decrypt(reply.getEncryptedEncPart(),key,KeyUsage.TGS_REP_ENCPART_SESSKEY);need(plain!=null);
            part=KrbCodec.decode(plain,EncTgsRepPart.class);
            need(Arrays.equals(plain,KrbCodec.encode(part)));
            checks.put("reply_authenticated",true);
            need(boundPart(part,original,realm,nonce,now));
            checks.put("nonce_client_server_bound",true);checks.put("renewed_times_bound",true);
            renewedLifetime=(int)((part.getEndTime().getTime()-part.getStartTime().getTime())/1000);
            need(!Arrays.equals(ticketBytes,KrbCodec.encode(reply.getTicket()))
                && !Arrays.equals(key.getKeyData(),part.getKey().getKeyData()));
            checks.put("fresh_ticket_and_key",true);
            stage="reply_controls";
            byte[] wrong=decrypt(reply.getEncryptedEncPart(),key,KeyUsage.TGS_REP_ENCPART_SUBKEY);
            try { need(wrong==null);replyControls++; } finally { if(wrong!=null)Arrays.fill(wrong,(byte)0); }
            EncryptedData changed=KrbCodec.decode(KrbCodec.encode(reply.getEncryptedEncPart()),EncryptedData.class);
            changed.getCipher()[changed.getCipher().length-1]^=1;
            try {
                wrong=decrypt(changed,key,KeyUsage.TGS_REP_ENCPART_SESSKEY);
                try { need(wrong==null);replyControls++; } finally { if(wrong!=null)Arrays.fill(wrong,(byte)0); }
            } finally { Arrays.fill(changed.getCipher(),(byte)0); }
            EncTgsRepPart altered=KrbCodec.decode(plain,EncTgsRepPart.class);altered.setNonce(nonce^1);
            need(!boundPart(altered,original,realm,nonce,now));replyControls++;
            altered.setNonce(nonce);altered.setRenewTill(new KerberosTime(part.getRenewTill().getTime()+1000));
            need(!boundPart(altered,original,realm,nonce,now));replyControls++;
            Arrays.fill(altered.getKey().getKeyData(),(byte)0);
            need(replyControls==4);checks.put("reply_controls",true);stage="completed";
        } finally {
            close();
            for(byte[] bytes:new byte[][]{bodyBytes,ticketBytes,authBytes,badRequest,goodRequest,badReply,goodReply,plain})
                if(bytes!=null)Arrays.fill(bytes,(byte)0);
            Arrays.fill(key.getKeyData(),(byte)0);
            if(part!=null && part.getKey()!=null)Arrays.fill(part.getKey().getKeyData(),(byte)0);
            if(encryptedBad!=null)Arrays.fill(encryptedBad.getCipher(),(byte)0);
            if(encryptedGood!=null)Arrays.fill(encryptedGood.getCipher(),(byte)0);
        }
    }
}
