/* Bootstrap qualification for the MIT KDC owner. This is a prerequisite for
 * the retained-rclone renewal experiment, not evidence of rclone renewal. */
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.client.*;
import org.apache.kerby.kerberos.kerb.type.ticket.*;

public final class MitKdcBootstrapProbe {
    static final List<Thread> tasks=new ArrayList<>();
    static final AtomicBoolean backgroundFailure=new AtomicBoolean();
    static <T> T bounded(Callable<T> operation) throws Exception {
        FutureTask<T> future=new FutureTask<>(operation);
        Thread worker=new Thread(future,"owned-mit-client-request"); worker.setDaemon(true); tasks.add(worker); worker.start();
        try { return future.get(10,TimeUnit.SECONDS); }
        catch(ExecutionException error) {
            Throwable cause=error.getCause(); if(cause instanceof Exception) throw (Exception)cause;
            throw new IllegalStateException("request_failed");
        } finally { future.cancel(true); worker.join(1000); }
    }
    static KOptions tgtOptions(String reader,String password) {
        KOptions options=new KOptions(); options.add(KrbOption.CLIENT_PRINCIPAL,reader);
        options.add(KrbOption.USE_PASSWD,true); options.add(KrbOption.USER_PASSWD,password);
        options.add(KrbOption.LIFE_TIME,120); options.add(KrbOption.RENEWABLE_TIME,180);
        options.add(KrbKdcOption.RENEWABLE,true); options.add(KrbKdcOption.RENEWABLE_OK,false);
        options.add(KrbKdcOption.FORWARDABLE,false); options.add(KrbKdcOption.PROXIABLE,false);
        return options;
    }
    static boolean typed(Throwable error,KrbErrorCode code) {
        Set<Throwable> seen=Collections.newSetFromMap(new IdentityHashMap<>());
        for(int i=0;error!=null && i<8 && seen.add(error);i++,error=error.getCause())
            if(error instanceof KrbException && ((KrbException)error).getKrbErrorCode()==code) return true;
        return false;
    }
    static long start(KrbTicket ticket) {
        var part=ticket.getEncKdcRepPart();
        return (part.getStartTime()==null?part.getAuthTime():part.getStartTime()).getTime()/1000;
    }
    static void need(boolean value) { if(!value) throw new IllegalStateException("bootstrap_predicate_failed"); }
    public static void main(String[] args) {
        PrintStream report=System.out;
        System.setOut(new PrintStream(OutputStream.nullOutputStream()));
        System.setErr(new PrintStream(OutputStream.nullOutputStream()));
        Thread.setDefaultUncaughtExceptionHandler((thread,error)->backgroundFailure.set(true));
        Map<String,Boolean> checks=new LinkedHashMap<>();
        for(String key:List.of("managed_contracts","lifecycle_controls","runtime_started","positive_tgt","short_renewable_service","wrong_password_rejected",
                "unknown_principal_rejected","healthy_after_rejection","tasks_reaped","new_threads_reaped","processes_reaped")) checks.put(key,false);
        Set<Long> processBaseline=ProcessHandle.current().descendants().map(ProcessHandle::pid).collect(java.util.stream.Collectors.toSet());
        Set<Thread> threadBaseline=null;
        MitKdcOwner owner=null; String stage="owner_construct",error="none"; boolean closed=false;
        int serviceLifetime=0,tgtLifetime=0,managedAssertions=0; long begun=System.nanoTime();
        try {
            need(args.length==0 && processBaseline.isEmpty());
            stage="managed_contracts";managedAssertions=MitKdcOwnerContracts.run();checks.put("managed_contracts",true);
            stage="owner_construct";
            owner=new MitKdcOwner(); final MitKdcOwner owned=owner;
            stage="owner_prepare"; owner.prepare(); stage="owner_start"; owner.start(); owner.healthy(); checks.put("runtime_started",true);
            threadBaseline=Set.copyOf(Thread.getAllStackTraces().keySet());
            stage="lifecycle_controls";
            MitKdcOwnerLifecycle.run();owner.healthy();checks.put("lifecycle_controls",true);
            stage="client_init";
            KrbConfig config=new KrbConfig();
            config.setBoolean(KrbConfigKey.KRB_DEBUG,false); config.setBoolean(KrbConfigKey.DNS_LOOKUP_KDC,false);
            config.setBoolean(KrbConfigKey.DNS_LOOKUP_REALM,false); config.setBoolean(KrbConfigKey.ALLOW_WEAK_CRYPTO,false);
            for(KrbConfigKey key:List.of(KrbConfigKey.PERMITTED_ENCTYPES,KrbConfigKey.DEFAULT_TKT_ENCTYPES,KrbConfigKey.DEFAULT_TGS_ENCTYPES))
                config.setString(key,"aes128-cts-hmac-sha1-96");
            KrbClient client=new KrbClient(config); client.setKdcRealm(owner.realm()); client.setKdcHost("127.0.0.1");
            client.setKdcTcpPort(18888); client.setAllowTcp(true); client.setAllowUdp(false); client.setTimeout(5000); client.init();
            stage="positive_tgt";
            TgtTicket tgt=bounded(()->client.requestTgt(tgtOptions(owned.reader(),owned.readerPassword())));
            long tgtStart=start(tgt),tgtEnd=tgt.getEncKdcRepPart().getEndTime().getTime()/1000;
            tgtLifetime=(int)(tgtEnd-tgtStart);
            need(tgtLifetime>=118 && tgtLifetime<=120 && (tgt.getEncKdcRepPart().getFlags().getFlags() & 0x00800000)!=0);
            need(tgt.getEncKdcRepPart().getRenewTill()!=null && tgt.getEncKdcRepPart().getRenewTill().getTime()/1000-tgtStart>=178
                && tgt.getEncKdcRepPart().getRenewTill().getTime()/1000-tgtStart<=180);
            checks.put("positive_tgt",true); owner.healthy();
            stage="service_ticket";
            KOptions options=new KOptions(); options.add(KrbOption.USE_TGT,tgt);
            options.add(KrbOption.SERVER_PRINCIPAL,"hdfs/127.0.0.1@"+owner.realm()); options.add(KrbOption.LIFE_TIME,10);
            options.add(KrbOption.RENEWABLE_TIME,60); options.add(KrbKdcOption.RENEWABLE,true); options.add(KrbKdcOption.RENEWABLE_OK,false);
            options.add(KrbKdcOption.FORWARDABLE,false); options.add(KrbKdcOption.PROXIABLE,false);
            SgtTicket service=bounded(()->client.requestSgt(options));
            long serviceStart=start(service),serviceEnd=service.getEncKdcRepPart().getEndTime().getTime()/1000;
            long renew=service.getEncKdcRepPart().getRenewTill()==null?0:service.getEncKdcRepPart().getRenewTill().getTime()/1000;
            serviceLifetime=(int)(serviceEnd-serviceStart);
            need(serviceLifetime>=8 && serviceLifetime<=10 && renew>serviceEnd && renew-serviceStart<=60
                && renew-serviceStart>=50 && (service.getEncKdcRepPart().getFlags().getFlags() & 0x00800000)!=0);
            checks.put("short_renewable_service",true);
            stage="wrong_password"; boolean denied=false;
            String wrong=owner.readerPassword().equals("0".repeat(32))?"1".repeat(32):"0".repeat(32);
            try { bounded(()->client.requestTgt(tgtOptions(owned.reader(),wrong))); }
            catch(KrbException failure) { denied=typed(failure,KrbErrorCode.KDC_ERR_PREAUTH_FAILED); }
            need(denied); checks.put("wrong_password_rejected",true);
            stage="unknown_principal"; denied=false;
            try { bounded(()->client.requestTgt(tgtOptions("absent@"+owned.realm(),owned.readerPassword()))); }
            catch(KrbException failure) { denied=typed(failure,KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN); }
            need(denied); checks.put("unknown_principal_rejected",true);
            stage="healthy_after_rejection";
            TgtTicket after=bounded(()->client.requestTgt(tgtOptions(owned.reader(),owned.readerPassword())));
            need(after!=null && !backgroundFailure.get()); owner.healthy(); checks.put("healthy_after_rejection",true);
            stage="completed";
        } catch(Exception failure) {
            managedAssertions=MitKdcOwnerContracts.observedAssertions();
            error=failure instanceof MitKdcOwner.Failure?((MitKdcOwner.Failure)failure).code.name():
                failure instanceof TimeoutException?"request_timeout":failure instanceof KrbException?"krb_failure":
                failure instanceof InterruptedException?"interrupted":"bootstrap_failed";
        } finally {
            for(Thread task:tasks) {
                if(task.isAlive()) task.interrupt();
                try { task.join(1000); } catch(InterruptedException ignored) { Thread.currentThread().interrupt(); }
            }
            checks.put("tasks_reaped",tasks.stream().noneMatch(Thread::isAlive));
            if(owner!=null) try { owner.close(); closed=true; } catch(Exception failure) { if(error.equals("none")) error="cleanup_failed"; }
            checks.put("processes_reaped",ProcessHandle.current().descendants().map(ProcessHandle::pid).collect(java.util.stream.Collectors.toSet()).equals(processBaseline));
            if(threadBaseline!=null) {
                Set<Thread> retained=threadBaseline;
                checks.put("new_threads_reaped",Thread.getAllStackTraces().keySet().stream().noneMatch(t->t.isAlive() && !retained.contains(t)));
            }
        }
        Map<String,Object> ownerReport=owner==null?Map.of():owner.projection();
        boolean passed=error.equals("none") && closed && checks.values().stream().allMatch(Boolean::booleanValue)
            && Boolean.FALSE.equals(ownerReport.get("forced")) && Boolean.FALSE.equals(ownerReport.get("descendants_seen"))
            && Boolean.FALSE.equals(ownerReport.get("stream_failure")) && !backgroundFailure.get();
        Map<String,Object> output=new LinkedHashMap<>(); output.put("schema_version",1); output.put("scope","mit_kdc_bootstrap_only");
        output.put("success",passed); output.put("stage",stage); output.put("error",error); output.put("checks",checks); output.put("owner",ownerReport);
        output.put("tasks",tasks.size()); output.put("managed_assertions",managedAssertions); output.put("tgt_lifetime_seconds",tgtLifetime); output.put("service_lifetime_seconds",serviceLifetime);
        output.put("lifecycle_checks",MitKdcOwnerLifecycle.projection());output.put("lifecycle_children",MitKdcOwnerLifecycle.children());
        output.put("duration_ms",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-begun)); output.put("cleanup_complete",closed);
        for(String claim:List.of("renewal_verified","rclone_verified","provider_accepted","application_accepted","vendor_accepted","vulnerability_audited")) output.put(claim,false);
        try { report.println(new ObjectMapper().writeValueAsString(output)); } catch(Exception ignored) { System.exit(3); }
        System.exit(passed?0:2);
    }
}
