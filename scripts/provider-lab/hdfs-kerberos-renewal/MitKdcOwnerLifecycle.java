/* Hosted process controls; synthetic children run only inside the admitted image. */
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public final class MitKdcOwnerLifecycle {
    static final Map<String,Boolean> checks=new LinkedHashMap<>();
    static int childCount;
    static {
        for(String name:new String[]{"graceful_termination","forced_termination_rejected","output_overflow_rejected","descendant_rejected"})
            checks.put(name,false);
    }
    static void need(boolean value) { if(!value) throw new IllegalStateException("lifecycle_predicate_failed"); }
    static void runCase(String mode,String name,MitKdcOwner.Code expected) throws Exception {
        MitKdcOwner owner=new MitKdcOwner();
        MitKdcOwner.Child child=null;
        boolean rejected=false,closed=false;
        try {
            child=owner.new Child(MitKdcLifecycleChild.builder(mode).start(),new byte[0]);
            owner.children.add(child);childCount++;child.begin();
            long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
            while(true) {
                try { child.check(); }
                catch(MitKdcOwner.Failure failure) {
                    need(expected!=null && failure.code==expected);rejected=true;break;
                }
                need(child.process.isAlive() && System.nanoTime()<until);
                if(expected==null && child.stdout.bytes>0) break;
                Thread.sleep(20);
            }
            child.finish(true);owner.close();closed=true;
            Map<String,Object> projection=owner.projection();
            need(child.finished && !child.process.isAlive() && child.descendants.stream().noneMatch(ProcessHandle::isAlive));
            need(Boolean.TRUE.equals(projection.get("children_reaped")) && Boolean.TRUE.equals(projection.get("streams_reaped"))
                && Boolean.TRUE.equals(projection.get("private_material_removed")));
            need(!child.stdout.failed && !child.stderr.failed && !child.inputFailed);
            if(mode.equals("hold")) need(!rejected && !owner.forced && !owner.descendantsSeen && !owner.streamFailure);
            if(mode.equals("term_hold")) need(!rejected && owner.forced && !owner.descendantsSeen && !owner.streamFailure);
            if(mode.equals("overflow")) need(rejected && child.stdout.overflow && owner.streamFailure && !owner.forced && !owner.descendantsSeen);
            if(mode.equals("descendant")) {
                need(rejected && owner.descendantsSeen && owner.streamFailure && !owner.forced && child.descendants.size()==1);
                childCount+=child.descendants.size();
            }
            checks.put(name,true);
        } finally {
            if(!closed) owner.close();
        }
    }
    public static void run() throws Exception {
        need(childCount==0 && checks.values().stream().noneMatch(Boolean::booleanValue));
        runCase("hold","graceful_termination",null);
        runCase("term_hold","forced_termination_rejected",null);
        runCase("overflow","output_overflow_rejected",MitKdcOwner.Code.output_bound);
        runCase("descendant","descendant_rejected",MitKdcOwner.Code.child_descendant);
        need(childCount==5 && checks.values().stream().allMatch(Boolean::booleanValue));
    }
    public static Map<String,Boolean> projection() { return Map.copyOf(checks); }
    public static int children() { return childCount; }
}
