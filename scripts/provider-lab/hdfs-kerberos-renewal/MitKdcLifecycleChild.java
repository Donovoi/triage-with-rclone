/* Synthetic child used only by the contained owner lifecycle controls. */
import java.nio.file.Path;
import java.util.List;

public final class MitKdcLifecycleChild {
    static final String JAVA="/opt/java/openjdk/bin/java";
    static ProcessBuilder builder(String mode) {
        if(!List.of("hold","term_hold","overflow","descendant").contains(mode))
            throw new IllegalArgumentException("mode_invalid");
        ProcessBuilder builder=new ProcessBuilder(JAVA,"-Xmx64m","-Djava.io.tmpdir=/work/tmp",
            "-Duser.home=/work/home","-cp","/opt/rpc/classes","MitKdcLifecycleChild",mode);
        builder.directory(Path.of("/work/home").toFile());builder.environment().clear();
        builder.environment().put("PATH","/opt/java/openjdk/bin:/usr/bin:/bin");
        builder.environment().put("LANG","C");builder.environment().put("LC_ALL","C");
        return builder;
    }
    public static void main(String[] args) throws Exception {
        if(args.length!=1 || !List.of("hold","term_hold","overflow","descendant").contains(args[0])) System.exit(2);
        String mode=args[0];
        if(mode.equals("term_hold")) Runtime.getRuntime().addShutdownHook(new Thread(()->{
            try { Thread.sleep(60000); } catch(InterruptedException ignored) { Thread.currentThread().interrupt(); }
        },"synthetic-delayed-shutdown"));
        if(mode.equals("descendant")) builder("hold").inheritIO().start();
        System.out.write(new byte[mode.equals("overflow")?65537:1]);System.out.flush();
        Thread.sleep(60000);
    }
}
