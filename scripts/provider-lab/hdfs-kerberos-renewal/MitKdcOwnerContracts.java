/* Managed contracts for the exact helpers used by the native owner. Reads only
 * the immutable template and in-memory streams; launches no native processes. */
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

public final class MitKdcOwnerContracts {
    public static final int EXPECTED_ASSERTIONS=68;
    private static int assertions;
    public static int observedAssertions() { return assertions; }
    interface Action { void run() throws Exception; }
    static void check(boolean value) {
        assertions++; if(!value) throw new IllegalStateException("managed_contract_failed");
    }
    static void rejected(Action action,MitKdcOwner.Code expected) throws Exception {
        boolean failed=false;
        try { action.run(); } catch(MitKdcOwner.Failure failure) { failed=failure.code==expected; }
        check(failed);
    }
    public static int run() throws Exception {
        assertions=0;
        byte[] raw=MitKdcOwner.boundedFile(MitKdcOwner.TEMPLATE,16384);
        String[][] inputs={
            {"012345abcdef","abcdef012345","0123456789abcdef0123456789abcdef","fedcba9876543210fedcba9876543210"},
            {"987654fedcba","fedcba987654","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}};
        String[] hashes={"2bb708bdf51f51ee9bbe6fb50916c4eff1a234c5b53781cc08c761d6ce4e3690",
            "0b04bf44ce49ffde7b294038b1b49a5e053ee41671818e5cfa6f2d107d28ea0a"};
        ObjectMapper mapper=new ObjectMapper();
        for(int i=0;i<inputs.length;i++) {
            String[] args=inputs[i];var plan=MitKdcOwner.render(raw,args[0],args[1],args[2],args[3]);
            check(MitKdcOwner.hash(mapper.writeValueAsBytes(plan)).equals(hashes[i]));
        }
        String[] good=inputs[0];byte[] changed=raw.clone();changed[changed.length-1]^=1;
        rejected(()->MitKdcOwner.render(changed,good[0],good[1],good[2],good[3]),MitKdcOwner.Code.plan_invalid);
        rejected(()->MitKdcOwner.render(null,good[0],good[1],good[2],good[3]),MitKdcOwner.Code.plan_invalid);
        String[] bad={null,"","../escape","012345abcde\n","Ｆ".repeat(12),"f".repeat(33)};
        for(int slot=0;slot<4;slot++) for(String value:bad) {
            String[] args=good.clone();args[slot]=value;
            rejected(()->MitKdcOwner.render(raw,args[0],args[1],args[2],args[3]),MitKdcOwner.Code.plan_invalid);
        }
        rejected(()->MitKdcOwner.render(raw,good[0],good[1],good[2],good[2]),MitKdcOwner.Code.plan_invalid);
        for(int size:new int[]{0,65536,65537}) {
            MitKdcOwner.Drain drain=new MitKdcOwner.Drain(new ByteArrayInputStream(new byte[size]));drain.run();
            check(drain.bytes==size && drain.overflow==(size>65536) && !drain.failed);
        }
        MitKdcOwner.Drain broken=new MitKdcOwner.Drain(new InputStream(){@Override public int read() throws IOException { throw new IOException(); }});
        broken.run();check(broken.failed && !broken.overflow);
        for(String name:MitKdcOwner.PRIVATE_LIBRARIES)check(MitKdcOwner.allowedMappedFile("/opt/mit/lib/"+name));
        for(String name:MitKdcOwner.BASE_LIBRARIES)check(MitKdcOwner.allowedMappedFile("/usr/lib/x86_64-linux-gnu/"+name));
        check(MitKdcOwner.allowedMappedFile("/opt/mit/bin/krb5kdc"));
        check(MitKdcOwner.allowedMappedFile("/opt/mit/lib/krb5/plugins/kdb/db2.so"));
        for(String file:new String[]{null,"/","/tmp/libkrb5.so.3","/opt/mit/lib/../lib/libkrb5.so.3",
            "/opt/mit/lib/libcrypto.so.3","/opt/mit/lib/libkrb5.so.3 (deleted)","/usr/lib/x86_64-linux-gnu/libkrb5.so.3","/opt/mit/lib/krb5/plugins/kdb/ldap.so"})
            check(!MitKdcOwner.allowedMappedFile(file));
        String[] listener={"0:","0100007F:49C8","00000000:0000","0A","0","0","0","10001","0","123"};
        check(MitKdcOwner.validateOwnedSocket("tcp",listener));
        String[] connected=listener.clone();connected[2]="0100007F:C001";connected[3]="01";
        check(!MitKdcOwner.validateOwnedSocket("tcp",connected));
        for(int index:new int[]{1,2,7,3}) {
            String[] row=listener.clone();row[index]=index==1?"00000000:49C8":index==2?"0100007F:C001":index==7?"0":"01";
            rejected(()->MitKdcOwner.validateOwnedSocket("tcp",row),MitKdcOwner.Code.listener_mismatch);
        }
        for(String table:List.of("tcp6","udp","udp6"))
            rejected(()->MitKdcOwner.validateOwnedSocket(table,listener),MitKdcOwner.Code.listener_mismatch);
        Arrays.fill(raw,(byte)0);Arrays.fill(changed,(byte)0);
        if(assertions!=EXPECTED_ASSERTIONS)throw new IllegalStateException("managed_count_mismatch");
        return assertions;
    }
}
