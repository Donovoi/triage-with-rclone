/* Authenticated evidence for owned MIT service renewal. No network or file I/O. */
import java.util.*;
import org.apache.kerby.kerberos.kerb.*;
import org.apache.kerby.kerberos.kerb.crypto.*;
import org.apache.kerby.kerberos.kerb.type.ap.ApReq;
import org.apache.kerby.kerberos.kerb.type.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.type.base.*;
import org.apache.kerby.kerberos.kerb.type.kdc.*;
import org.apache.kerby.kerberos.kerb.type.ticket.*;

final class MitRenewalEvidence implements AutoCloseable {
    enum Code { wire_invalid }
    static final class Failure extends Exception {
        final Code code;
        Failure(Code value) { super(value.name()); code=value; }
    }
    static void need(boolean value,Code code) throws Failure { if(!value)throw new Failure(code); }
    final String realm,reader,variant;
    final boolean renewable;
    final byte[] tgtBytes,serviceBytes;
    final EncryptionKey tgtKey,serviceKey;
    final EncKdcRepPart original;
    byte[] freshTicket;
    EncryptionKey freshKey;
    int requests,authenticatorControls,renewalReplies,ordinaryReplies,replyControls;
    boolean closed;
    final Map<String,Boolean> renewalFields=new LinkedHashMap<>();
    static final class Request {
        final boolean renew;final String ticketKind;final int usage,nonce;final long requestTime;
        boolean replied;
        Request(boolean renew,String ticketKind,int usage,int nonce,long requestTime) {
            this.renew=renew;this.ticketKind=ticketKind;this.usage=usage;this.nonce=nonce;this.requestTime=requestTime;
        }
    }
    static final class Reply {
        final String type;final int error;final boolean fresh;
        Reply(String type,int error,boolean fresh){this.type=type;this.error=error;this.fresh=fresh;}
    }
    MitRenewalEvidence(TgtTicket tgt,SgtTicket service,String realm,String reader,boolean renewable,String variant) throws Exception {
        need(realm!=null && reader!=null && List.of("original","patched").contains(variant),Code.wire_invalid);
        this.realm=realm;this.reader=reader;this.renewable=renewable;this.variant=variant;
        tgtBytes=KrbCodec.encode(tgt.getTicket());serviceBytes=KrbCodec.encode(service.getTicket());
        tgtKey=new EncryptionKey(17,tgt.getSessionKey().getKeyData().clone());
        serviceKey=new EncryptionKey(17,service.getSessionKey().getKeyData().clone());
        need(tgt.getSessionKey().getKeyType().getValue()==17 && service.getSessionKey().getKeyType().getValue()==17
            && tgtKey.getKeyData().length==16 && serviceKey.getKeyData().length==16,Code.wire_invalid);
        original=service.getEncKdcRepPart();
    }
    synchronized Request request(byte[] raw) throws Exception {
        need(!closed && raw.length>0 && raw.length<=65536 && requests<4,Code.wire_invalid);
        TgsReq req=KrbCodec.decode(raw,TgsReq.class);
        need(req.getPvno()==5 && req.getMsgType()==KrbMessageType.TGS_REQ && Arrays.equals(raw,KrbCodec.encode(req)),Code.wire_invalid);
        KdcReqBody body=req.getReqBody();
        need(body!=null && realm.equals(body.getRealm()) && body.getSname()!=null
            && body.getSname().getNameStrings().equals(List.of("hdfs","127.0.0.1"))
            && body.getKdcOptions()!=null && req.getPaData()!=null,Code.wire_invalid);
        boolean renew=body.getKdcOptions().isFlagSet(KdcOption.RENEW);
        var entries=req.getPaData().getElements();need(entries!=null && entries.size()>=1 && entries.size()<=4,Code.wire_invalid);
        byte[] encodedAp=null;Set<Integer> seen=new HashSet<>();
        for(var entry:entries){
            need(entry!=null && entry.getPaDataType()!=null && entry.getPaDataValue()!=null,Code.wire_invalid);
            int type=entry.getPaDataType().getValue();need((type==1 || type==128) && seen.add(type)
                && entry.getPaDataValue().length<=65536,Code.wire_invalid);
            if(type==1)encodedAp=entry.getPaDataValue();
        }
        need(encodedAp!=null,Code.wire_invalid);ApReq ap=KrbCodec.decode(encodedAp,ApReq.class);
        need(ap.getPvno()==5 && ap.getMsgType()==KrbMessageType.AP_REQ && Arrays.equals(encodedAp,KrbCodec.encode(ap)) && ap.getTicket()!=null,Code.wire_invalid);
        byte[] ticket=KrbCodec.encode(ap.getTicket()),bodyBytes=KrbCodec.encode(body);
        try {
            String kind=Arrays.equals(ticket,tgtBytes)?"issued_tgt":Arrays.equals(ticket,serviceBytes)?"issued_service":"unknown";
            need(renew?renewable && kind.equals("issued_service"):kind.equals("issued_tgt"),Code.wire_invalid);
            EncryptionKey key=renew?serviceKey:tgtKey;
            int usage=observeAuthenticator(ap.getEncryptedAuthenticator(),key,bodyBytes);
            need(usage==(renew && variant.equals("original")?11:7),Code.wire_invalid);
            if(renew)need(body.getKdcOptions().isFlagSet(KdcOption.RENEWABLE),Code.wire_invalid);
            authenticatorControls+=8;requests++;
            return new Request(renew,kind,usage,body.getNonce(),System.currentTimeMillis());
        } finally {Arrays.fill(ticket,(byte)0);Arrays.fill(bodyBytes,(byte)0);}
    }
    synchronized Reply response(byte[] raw,Request request) throws Exception {
        need(!closed && request!=null && !request.replied && raw.length>2 && raw.length<=65536,Code.wire_invalid);
        if(Byte.toUnsignedInt(raw[0])==0x7e){
            KrbError error=KrbCodec.decode(raw,KrbError.class);
            need(Arrays.equals(raw,KrbCodec.encode(error)) && error.getErrorCode()!=null
                && request.renew && variant.equals("original") && request.usage==11
                && error.getErrorCode().getValue()==31,Code.wire_invalid);
            request.replied=true;return new Reply("krb_error",31,false);
        }
        need(!request.renew || variant.equals("patched"),Code.wire_invalid);
        TgsRep reply=KrbCodec.decode(raw,TgsRep.class);
        need(reply.getPvno()==5 && reply.getMsgType()==KrbMessageType.TGS_REP && Arrays.equals(raw,KrbCodec.encode(reply))
            && realm.equals(reply.getCrealm()) && reply.getCname()!=null
            && reply.getCname().getNameStrings().equals(List.of(reader)) && reply.getTicket()!=null
            && realm.equals(reply.getTicket().getRealm()) && reply.getTicket().getSname().getNameStrings().equals(List.of("hdfs","127.0.0.1")),Code.wire_invalid);
        EncryptionKey key=request.renew?serviceKey:tgtKey;
        byte[] plain=decryptAuthenticator(reply.getEncryptedEncPart(),key,KeyUsage.TGS_REP_ENCPART_SESSKEY);
        need(plain!=null,Code.wire_invalid);EncTgsRepPart part=null;
        try {
            part=KrbCodec.decode(plain,EncTgsRepPart.class);
            need(Arrays.equals(plain,KrbCodec.encode(part)) && part.getNonce()==request.nonce
                && realm.equals(part.getSrealm()) && part.getSname()!=null
                && part.getSname().getNameStrings().equals(List.of("hdfs","127.0.0.1"))
                && part.getKey()!=null && part.getKey().getKeyType().getValue()==17 && part.getKey().getKeyData().length==16
                && part.getStartTime()!=null && part.getEndTime()!=null
                && part.getEndTime().getTime()>System.currentTimeMillis()
                && part.getEndTime().getTime()>original.getEndTime().getTime(),Code.wire_invalid);
            if(request.renew){
                renewalFields.putAll(partBindings(part,original,realm,request.nonce,request.requestTime));
                need(renewalFields.values().stream().allMatch(Boolean::booleanValue),Code.wire_invalid);
                renewalReplies++;
            }else ordinaryReplies++;
            byte[] ticket=KrbCodec.encode(reply.getTicket());
            need(!Arrays.equals(ticket,serviceBytes) && !Arrays.equals(part.getKey().getKeyData(),serviceKey.getKeyData())
                && freshTicket==null && freshKey==null,Code.wire_invalid);
            freshTicket=ticket;freshKey=new EncryptionKey(17,part.getKey().getKeyData().clone());
            replyMutationControls(reply,part,key,request);request.replied=true;
            return new Reply("tgs_rep",0,true);
        }finally {Arrays.fill(plain,(byte)0);if(part!=null && part.getKey()!=null)Arrays.fill(part.getKey().getKeyData(),(byte)0);}
    }
    private void replyMutationControls(TgsRep reply,EncTgsRepPart part,EncryptionKey key,Request req) throws Exception {
        byte[] bad=decryptAuthenticator(reply.getEncryptedEncPart(),key,KeyUsage.TGS_REP_ENCPART_SUBKEY);
        try {need(bad==null,Code.wire_invalid);replyControls++;}finally{if(bad!=null)Arrays.fill(bad,(byte)0);}
        EncryptedData changed=KrbCodec.decode(KrbCodec.encode(reply.getEncryptedEncPart()),EncryptedData.class);
        changed.getCipher()[changed.getCipher().length-1]^=1;
        try {bad=decryptAuthenticator(changed,key,KeyUsage.TGS_REP_ENCPART_SESSKEY);
            try{need(bad==null,Code.wire_invalid);replyControls++;}finally{if(bad!=null)Arrays.fill(bad,(byte)0);}
        }finally{Arrays.fill(changed.getCipher(),(byte)0);}
        if(req.renew){
            need(!boundPart(part,original,realm,req.nonce^1,req.requestTime),Code.wire_invalid);replyControls++;
            need(!boundPart(part,original,realm+"X",req.nonce,req.requestTime),Code.wire_invalid);replyControls++;
        }
    }
    private static int[] element(byte[] bytes,int offset,int tag) throws Failure {
        need(offset>=0 && offset+2<=bytes.length && Byte.toUnsignedInt(bytes[offset])==tag,Code.wire_invalid);
        int first=Byte.toUnsignedInt(bytes[offset+1]),start=offset+2,length=first;
        if((first&128)!=0){
            int count=first&127;need(count>=1 && count<=3 && start+count<=bytes.length && bytes[start]!=0,Code.wire_invalid);
            length=0;for(int i=0;i<count;i++)length=(length<<8)|Byte.toUnsignedInt(bytes[start+i]);start+=count;
            need(length>=128 && (count==1 || length>=(1<<(8*(count-1)))),Code.wire_invalid);
        }
        need(length>=0 && length<=65536 && start+length<=bytes.length,Code.wire_invalid);
        return new int[]{start,start+length};
    }
    private static byte[] mechanismAp(byte[] token) throws Failure {
        int[] outer=element(token,0,0x60);need(outer[1]==token.length,Code.wire_invalid);
        byte[] prefix={0x06,0x09,0x2a,(byte)0x86,0x48,(byte)0x86,(byte)0xf7,0x12,0x01,0x02,0x02,0x01,0x00};
        need(outer[1]-outer[0]>prefix.length,Code.wire_invalid);
        for(int i=0;i<prefix.length;i++)need(token[outer[0]+i]==prefix[i],Code.wire_invalid);
        int begin=outer[0]+prefix.length;int[] ap=element(token,begin,0x6e);need(ap[1]==outer[1],Code.wire_invalid);
        return Arrays.copyOfRange(token,begin,outer[1]);
    }
    private static void gssChecksum(Authenticator auth) throws Exception {
        need(auth.getCksum()!=null,Code.wire_invalid);
        byte[] encoded=KrbCodec.encode(auth.getCksum());
        try{
            int[] seq=element(encoded,0,0x30);need(seq[1]==encoded.length,Code.wire_invalid);
            int[] type=element(encoded,seq[0],0xa0),integer=element(encoded,type[0],0x02);
            need(integer[1]==type[1] && integer[1]-integer[0]==3 && encoded[integer[0]]==0
                && Byte.toUnsignedInt(encoded[integer[0]+1])==128 && encoded[integer[0]+2]==3,Code.wire_invalid);
            int[] value=element(encoded,type[1],0xa1),octets=element(encoded,value[0],0x04);
            need(value[1]==seq[1] && octets[1]==value[1] && octets[1]-octets[0]==24,Code.wire_invalid);
            int begin=octets[0];need(encoded[begin]==16 && encoded[begin+1]==0 && encoded[begin+2]==0 && encoded[begin+3]==0,Code.wire_invalid);
            for(int i=4;i<20;i++)need(encoded[begin+i]==0,Code.wire_invalid);
            int flags=Byte.toUnsignedInt(encoded[begin+20]) | Byte.toUnsignedInt(encoded[begin+21])<<8
                | Byte.toUnsignedInt(encoded[begin+22])<<16 | Byte.toUnsignedInt(encoded[begin+23])<<24;
            need((flags&32)!=0 && (flags&~62)==0,Code.wire_invalid);
        }finally{Arrays.fill(encoded,(byte)0);}
    }
    private byte[] serviceAp(byte[] raw,byte[] expected,EncryptionKey key) throws Exception {
        ApReq ap=KrbCodec.decode(raw,ApReq.class);
        need(ap.getPvno()==5 && ap.getMsgType()==KrbMessageType.AP_REQ && Arrays.equals(raw,KrbCodec.encode(ap))
            && ap.getTicket()!=null && realm.equals(ap.getTicket().getRealm())
            && ap.getTicket().getSname().getNameStrings().equals(List.of("hdfs","127.0.0.1")),Code.wire_invalid);
        byte[] ticket=KrbCodec.encode(ap.getTicket());
        try{need(Arrays.equals(ticket,expected),Code.wire_invalid);}finally{Arrays.fill(ticket,(byte)0);}
        byte[] plain=decryptAuthenticator(ap.getEncryptedAuthenticator(),key,KeyUsage.AP_REQ_AUTH);
        need(plain!=null,Code.wire_invalid);boolean keep=false;
        try{
            Authenticator auth=KrbCodec.decode(plain,Authenticator.class);byte[] canonical=KrbCodec.encode(auth);
            try{need(Arrays.equals(plain,canonical),Code.wire_invalid);}finally{Arrays.fill(canonical,(byte)0);}
            need(auth.getAuthenticatorVno()==5 && realm.equals(auth.getCrealm()) && auth.getCname()!=null
                && auth.getCname().getNameStrings().equals(List.of(reader)) && auth.getCname().getNameType().getValue()==1
                && auth.getSubKey()==null && auth.getAuthorizationData()==null && auth.getCtime()!=null
                && Math.abs(System.currentTimeMillis()-auth.getCtime().getTime())<=30000
                && auth.getCusec()>=0 && auth.getCusec()<1000000,Code.wire_invalid);
            gssChecksum(auth);keep=true;return plain;
        }finally{if(!keep)Arrays.fill(plain,(byte)0);}
    }
    private boolean rejectsServiceAp(byte[] raw,byte[] expected,EncryptionKey key) throws Exception {
        byte[] plain=null;
        try{plain=serviceAp(raw,expected,key);return false;}catch(Failure rejected){return true;}
        finally{if(plain!=null)Arrays.fill(plain,(byte)0);}
    }
    int initialApBindings,freshApBindings,apControls;
    synchronized void verifyMechanismToken(byte[] token,boolean afterRenewal) throws Exception {
        need(!closed && token!=null && token.length>16 && token.length<=65536,Code.wire_invalid);
        byte[] expected=afterRenewal?freshTicket:serviceBytes;EncryptionKey key=afterRenewal?freshKey:serviceKey;
        need(expected!=null && key!=null && (afterRenewal?freshApBindings==0:initialApBindings==0),Code.wire_invalid);
        byte[] raw=mechanismAp(token),plain=null,wrongTicket=expected.clone(),wrongKey=key.getKeyData().clone();
        wrongTicket[wrongTicket.length-1]^=1;wrongKey[0]^=1;
        try{
            plain=serviceAp(raw,expected,key);
            need(rejectsServiceAp(raw,wrongTicket,key),Code.wire_invalid);apControls++;
            need(rejectsServiceAp(raw,expected,new EncryptionKey(17,wrongKey)),Code.wire_invalid);apControls++;
            for(boolean corrupt:List.of(false,true)){
                ApReq modified=KrbCodec.decode(raw,ApReq.class);
                modified.setEncryptedAuthenticator(EncryptionHandler.encrypt(plain,key,corrupt?KeyUsage.AP_REQ_AUTH:KeyUsage.TGS_REQ_AUTH));
                if(corrupt)modified.getEncryptedAuthenticator().getCipher()[modified.getEncryptedAuthenticator().getCipher().length-1]^=1;
                byte[] altered=KrbCodec.encode(modified);
                try{need(rejectsServiceAp(altered,expected,key),Code.wire_invalid);apControls++;}
                finally{Arrays.fill(altered,(byte)0);Arrays.fill(modified.getEncryptedAuthenticator().getCipher(),(byte)0);}
            }
            if(afterRenewal)freshApBindings++;else initialApBindings++;
        }finally{Arrays.fill(raw,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);Arrays.fill(wrongTicket,(byte)0);Arrays.fill(wrongKey,(byte)0);}
    }
    synchronized void verifyKdcOutcome() throws Exception {
        need(!closed && freshTicket!=null && freshKey!=null && authenticatorControls==8*requests,Code.wire_invalid);
        boolean positive=renewable && variant.equals("patched");
        need(positive?requests==1 && renewalReplies==1 && ordinaryReplies==0 && replyControls==4
            :requests==(renewable?2:1) && renewalReplies==0 && ordinaryReplies==1 && replyControls==2,Code.wire_invalid);
    }
    synchronized Map<String,Object> projection(){
        Map<String,Object> out=new LinkedHashMap<>();out.put("requests",requests);out.put("authenticator_controls",authenticatorControls);
        out.put("renewal_replies",renewalReplies);out.put("ordinary_replies",ordinaryReplies);out.put("reply_controls",replyControls);
        out.put("renewal_fields",new LinkedHashMap<>(renewalFields));out.put("closed",closed);
        out.put("initial_ap_bindings",initialApBindings);out.put("fresh_ap_bindings",freshApBindings);out.put("ap_controls",apControls);
        out.put("renewal_verified",false);return out;
    }
    @Override public synchronized void close(){
        for(byte[] bytes:new byte[][]{tgtBytes,serviceBytes,tgtKey.getKeyData(),serviceKey.getKeyData(),freshTicket,freshKey==null?null:freshKey.getKeyData()})
            if(bytes!=null)Arrays.fill(bytes,(byte)0);
        closed=true;
    }
    private byte[] decryptAuthenticator(EncryptedData encrypted, EncryptionKey key, KeyUsage usage) throws Exception {
        need(encrypted != null && encrypted.getEType().getValue() == 17 && key != null
            && key.getKeyType().getValue() == 17 && key.getKeyData().length == 16
            && encrypted.getCipher() != null && encrypted.getCipher().length >= 28
            && encrypted.getCipher().length <= 4096, Code.wire_invalid);
        byte[] cipher = encrypted.getCipher().clone();
        try { return EncryptionHandler.decrypt(cipher, key, usage); }
        catch (KrbException failure) {
            if (failure.getKrbErrorCode() == org.apache.kerby.kerberos.kerb.KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY) return null;
            throw failure;
        } finally { Arrays.fill(cipher, (byte)0); }
    }
    private void bindAuthenticator(byte[] plain, byte[] requestBody, EncryptionKey key) throws Exception {
        need(plain != null && plain.length > 2 && plain.length <= 4096, Code.wire_invalid);
        Authenticator auth;
        try { auth = KrbCodec.decode(plain, Authenticator.class); }
        catch (KrbException malformed) { throw new Failure(Code.wire_invalid); }
        byte[] canonical = KrbCodec.encode(auth);
        try {
            need(Arrays.equals(plain, canonical) && auth.getAuthenticatorVno() == 5
                && realm.equals(auth.getCrealm()) && auth.getCname() != null
                && auth.getCname().getNameStrings().equals(List.of(reader))
                && auth.getCname().getNameType().getValue() == 1
                && auth.getSubKey() == null && auth.getAuthorizationData() == null
                && auth.getCusec() >= 0 && auth.getCusec() < 1000000 && auth.getCtime() != null
                && Math.abs(System.currentTimeMillis()-auth.getCtime().getTime()) <= 30000
                && auth.getCksum() != null && auth.getCksum().getCksumtype().getValue() == 15
                && auth.getCksum().getChecksum().length == 12
                && CheckSumHandler.verifyWithKey(auth.getCksum(), requestBody, key.getKeyData(), KeyUsage.TGS_REQ_AUTH_CKSUM),
                Code.wire_invalid);
        } finally { Arrays.fill(canonical, (byte)0); }
    }
    private int classifyAuthenticator(EncryptedData encrypted, EncryptionKey key, byte[] requestBody) throws Exception {
        byte[] seven = null, eleven = null;
        try {
            seven = decryptAuthenticator(encrypted, key, KeyUsage.TGS_REQ_AUTH);
            eleven = decryptAuthenticator(encrypted, key, KeyUsage.AP_REQ_AUTH);
            need((seven == null) != (eleven == null), Code.wire_invalid);
            bindAuthenticator(seven == null ? eleven : seven, requestBody, key);
            return seven == null ? 11 : 7;
        } finally {
            if (seven != null) Arrays.fill(seven, (byte)0);
            if (eleven != null) Arrays.fill(eleven, (byte)0);
        }
    }
    private boolean authenticatorRejected(EncryptedData encrypted, EncryptionKey key, byte[] requestBody) throws Exception {
        try { classifyAuthenticator(encrypted, key, requestBody); return false; }
        catch (Failure expected) { need(expected.code == Code.wire_invalid, Code.wire_invalid); return true; }
    }
    private int observeAuthenticator(EncryptedData encrypted, EncryptionKey key, byte[] requestBody) throws Exception {
        int usage = classifyAuthenticator(encrypted, key, requestBody), controls = 0;
        byte[] plain = decryptAuthenticator(encrypted, key, usage == 7 ? KeyUsage.TGS_REQ_AUTH : KeyUsage.AP_REQ_AUTH);
        byte[] wrongBody = requestBody.clone(), wrongBytes = key.getKeyData().clone();
        wrongBody[wrongBody.length-1] ^= 1; wrongBytes[0] ^= 1;
        try {
            // Independent controls cover both usages, corrupt ciphertext, wrong
            // key, changed body, invalid identity/version and trailing plaintext.
            for (KeyUsage testUsage : List.of(KeyUsage.TGS_REQ_AUTH, KeyUsage.AP_REQ_AUTH)) {
                EncryptedData test = EncryptionHandler.encrypt(plain, key, testUsage);
                try {
                    need(classifyAuthenticator(test, key, requestBody) == testUsage.getValue(), Code.wire_invalid); controls++;
                    test.getCipher()[test.getCipher().length-1] ^= 1;
                    need(authenticatorRejected(test, key, requestBody), Code.wire_invalid); controls++;
                } finally { Arrays.fill(test.getCipher(), (byte)0); }
            }
            need(authenticatorRejected(encrypted, new EncryptionKey(17, wrongBytes), requestBody), Code.wire_invalid); controls++;
            need(authenticatorRejected(encrypted, key, wrongBody), Code.wire_invalid); controls++;
            Authenticator wrongIdentity = KrbCodec.decode(plain, Authenticator.class);
            wrongIdentity.setAuthenticatorVno(4);
            byte[] wrongPlain = KrbCodec.encode(wrongIdentity), trailing = Arrays.copyOf(plain, plain.length+1);
            try {
                for (byte[] badPlain : List.of(wrongPlain, trailing)) {
                    EncryptedData test = EncryptionHandler.encrypt(badPlain, key, KeyUsage.TGS_REQ_AUTH);
                    try { need(authenticatorRejected(test, key, requestBody), Code.wire_invalid); controls++; }
                    finally { Arrays.fill(test.getCipher(), (byte)0); }
                }
            } finally { Arrays.fill(wrongPlain, (byte)0); Arrays.fill(trailing, (byte)0); }
            need(controls == 8, Code.wire_invalid); return usage;
        } finally { Arrays.fill(plain, (byte)0); Arrays.fill(wrongBody, (byte)0); Arrays.fill(wrongBytes, (byte)0); }
    }

    static Map<String,Boolean> partBindings(EncTgsRepPart part,EncKdcRepPart original,String realm,int nonce,long requestTime) {
        Map<String,Boolean> fields=new LinkedHashMap<>();
        for(String name:List.of("fields_present","nonce","server","auth_time","start_time","validity","renewal_horizon","flags","key"))
            fields.put(name,false);
        boolean present=part.getFlags()!=null && part.getKey()!=null && part.getSname()!=null
            && part.getAuthTime()!=null && part.getStartTime()!=null && part.getEndTime()!=null && part.getRenewTill()!=null;
        fields.put("fields_present",present);if(!present)return fields;
        long start=part.getStartTime().getTime(),end=part.getEndTime().getTime();
        fields.put("nonce",part.getNonce()==nonce);
        fields.put("server",realm.equals(part.getSrealm()) && part.getSname().getNameStrings().equals(List.of("hdfs","127.0.0.1")));
        fields.put("auth_time",part.getAuthTime().getTime()==original.getAuthTime().getTime());
        fields.put("start_time",start>=original.getEndTime().getTime()+1000 && Math.abs(start-requestTime)<=3000);
        fields.put("validity",end-start>=8000 && end-start<=10000 && end>original.getEndTime().getTime());
        fields.put("renewal_horizon",part.getRenewTill().getTime()==original.getRenewTill().getTime() && end<=part.getRenewTill().getTime());
        fields.put("flags",(part.getFlags().getFlags() & 0x00800000)!=0 && (part.getFlags().getFlags() & 0x50000000)==0);
        fields.put("key",part.getKey().getKeyType()==EncryptionType.AES128_CTS_HMAC_SHA1_96 && part.getKey().getKeyData().length==16);
        return fields;
    }
    static boolean boundPart(EncTgsRepPart part,EncKdcRepPart original,String realm,int nonce,long requestTime) {
        return partBindings(part,original,realm,nonce,requestTime).values().stream().allMatch(Boolean::booleanValue);
    }
}
