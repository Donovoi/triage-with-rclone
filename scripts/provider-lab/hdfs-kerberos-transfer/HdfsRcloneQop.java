import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggingEvent;

/** Bounded, synchronous observation of completed server SASL handshakes. */
final class HdfsRcloneQop {
    private static final String CATEGORY = "org.apache.hadoop.hdfs.protocol.datatransfer.sasl.DataTransferSaslUtil";
    private static final String MESSAGE = "SaslServer: Verifying QOP: requested = [auth-conf], negotiated = auth-conf";
    private static final String SERVER = "org.apache.hadoop.hdfs.protocol.datatransfer.sasl.SaslDataTransferServer";
    private static final String XCEIVER = "org.apache.hadoop.hdfs.server.datanode.DataXceiver";
    private static final int[] EXPECTED = {0, 0, 1, 0, 2, 0, 2, 1, 0, 0};
    private static final int[] COUNTS = new int[10];
    private static final Object LOCK = new Object();
    private static final List<Thread> OWNED = new ArrayList<>();
    private static Set<Thread> baseline;
    private static Logger logger;
    private static Observer observer;
    private static Level originalLevel;
    private static boolean originalAdditivity, attempted, parserChecked;
    private static volatile boolean attached, restored = true;
    private static boolean failed, verified;
    private static int phase = -1, completed;
    private static long deadline;

    private static void need(boolean value) throws IOException {
        if (!value) throw new IOException("rclone_qop_invalid");
    }

    static boolean valid(String category, Level level, String message, boolean throwable,
                         StackTraceElement[] stack) {
        if (!CATEGORY.equals(category) || level != Level.DEBUG || !MESSAGE.equals(message)
                || throwable || stack == null || stack.length > 128) return false;
        int util = -1, server = -1, xceiver = -1;
        for (int i = 0; i < stack.length; i++) {
            var f = stack[i];
            if (f == null) return false;
            if (CATEGORY.equals(f.getClassName()) && "checkSaslComplete".equals(f.getMethodName())) {
                if (util != -1) return false;
                util = i;
            }
            if (SERVER.equals(f.getClassName()) && "doSaslHandshake".equals(f.getMethodName())) {
                if (server != -1) return false;
                server = i;
            }
            if (XCEIVER.equals(f.getClassName()) && "run".equals(f.getMethodName())) {
                if (xceiver != -1) return false;
                xceiver = i;
            }
        }
        return util >= 0 && util < server && server < xceiver;
    }

    private static final class Observer extends AppenderSkeleton {
        @Override protected void append(LoggingEvent event) {
            synchronized (LOCK) {
                try {
                    Thread thread = Thread.currentThread();
                    // Only this exact finite message is retained as a count. No raw event is stored.
                    if (!attached || phase < 0 || phase >= 10 || failed
                            || System.nanoTime() >= deadline || baseline.contains(thread)
                            || OWNED.contains(thread) || OWNED.size() >= 6
                            || COUNTS[phase] >= EXPECTED[phase]
                            || !valid(event.getLoggerName(), event.getLevel(), event.getRenderedMessage(),
                                event.getThrowableInformation() != null, thread.getStackTrace())) {
                        failed = true;
                        return;
                    }
                    OWNED.add(thread);
                    COUNTS[phase]++;
                } catch (Throwable ignored) { failed = true; }
            }
        }
        @Override public void close() { closed = true; }
        @Override public boolean requiresLayout() { return false; }
    }

    static void selfCheck() throws IOException {
        StackTraceElement[] stack = {
            new StackTraceElement(CATEGORY, "checkSaslComplete", "x", 1),
            new StackTraceElement(SERVER, "doSaslHandshake", "x", 1),
            new StackTraceElement(XCEIVER, "run", "x", 1)};
        need(valid(CATEGORY, Level.DEBUG, MESSAGE, false, stack));
        need(!valid(CATEGORY, Level.INFO, MESSAGE, false, stack));
        need(!valid(CATEGORY + "x", Level.DEBUG, MESSAGE, false, stack));
        need(!valid(CATEGORY, Level.DEBUG, MESSAGE, true, stack));
        need(!valid(CATEGORY, Level.DEBUG, MESSAGE, false, null));
        need(!valid(CATEGORY, Level.DEBUG, MESSAGE, false, new StackTraceElement[0]));
        need(!valid(CATEGORY, Level.DEBUG, MESSAGE, false, new StackTraceElement[129]));
        for (String bad : List.of("", MESSAGE + "x", MESSAGE.replace("auth-conf", "auth-int"),
                MESSAGE.replace("SaslServer", "SaslClient"), MESSAGE.replace("negotiated = auth-conf", "negotiated = null"))) {
            need(!valid(CATEGORY, Level.DEBUG, bad, false, stack));
        }
        need(!valid(CATEGORY, Level.DEBUG, MESSAGE, false, new StackTraceElement[]{stack[1], stack[0], stack[2]}));
        need(!valid(CATEGORY, Level.DEBUG, MESSAGE, false, new StackTraceElement[]{stack[0], stack[0], stack[1], stack[2]}));
        parserChecked = true;
    }

    static void open(long until) throws IOException {
            need(parserChecked && !attempted && restored && until > System.nanoTime());
            attempted = true;
            deadline = until;
            logger = Logger.getLogger(CATEGORY);
            need(!logger.getAllAppenders().hasMoreElements() && !logger.isDebugEnabled());
            originalLevel = logger.getLevel();
            originalAdditivity = logger.getAdditivity();
            observer = new Observer();
            restored = false;
            // Suppress parent delivery before enabling debug; restore the exact prior state later.
            logger.setAdditivity(false);
            logger.addAppender(observer);
            attached = logger.isAttached(observer);
            logger.setLevel(Level.DEBUG);
            need(attached && logger.isDebugEnabled() && !logger.getAdditivity());
    }

    static void begin(int next) throws IOException {
        synchronized (LOCK) {
            need(attached && !failed && phase == -1 && next == completed && next < 10);
            Set<Thread> seen = Thread.getAllStackTraces().keySet();
            need(seen.size() <= 256 && OWNED.stream().noneMatch(Thread::isAlive));
            baseline = Collections.newSetFromMap(new IdentityHashMap<>());
            baseline.addAll(seen);
            phase = next;
        }
    }

    static void end(int current) throws Exception {
        List<Thread> threads;
        synchronized (LOCK) {
            need(!failed && phase == current && COUNTS[current] == EXPECTED[current]);
            threads = List.copyOf(OWNED);
        }
        long until = Math.min(deadline, System.nanoTime() + TimeUnit.SECONDS.toNanos(3));
        for (Thread thread : threads) {
            long left = until - System.nanoTime();
            need(left > 0);
            thread.join(Math.max(1, TimeUnit.NANOSECONDS.toMillis(left)));
            need(!thread.isAlive());
        }
        synchronized (LOCK) {
            need(!failed && phase == current && COUNTS[current] == EXPECTED[current]);
            phase = -1;
            completed++;
            baseline = null;
        }
    }

    static void finish() throws IOException {
        synchronized (LOCK) {
            need(!failed && attached && completed == 10 && phase == -1 && OWNED.size() == 6
                    && OWNED.stream().noneMatch(Thread::isAlive));
            verified = true;
        }
        close();
        need(clean());
    }

    static void close() {
        // Never hold LOCK across logger/appender operations: an in-flight append owns the reverse order.
            if (restored) return;
            try {
                logger.setLevel(originalLevel);
                logger.removeAppender(observer);
                observer.close();
                attached = logger.isAttached(observer);
                logger.setAdditivity(originalAdditivity);
                restored = !attached && !logger.getAllAppenders().hasMoreElements()
                        && logger.getLevel() == originalLevel && logger.getAdditivity() == originalAdditivity;
            } catch (Throwable ignored) { restored = false; }
    }

    static boolean clean() {
        synchronized (LOCK) { return restored && !attached && OWNED.stream().noneMatch(Thread::isAlive); }
    }

    static String json() {
        synchronized (LOCK) {
            StringBuilder text = new StringBuilder("{\"attempted\":").append(attempted)
                .append(",\"parser_checked\":").append(parserChecked).append(",\"verified\":").append(verified && !failed)
                .append(",\"failed\":").append(failed).append(",\"attached\":").append(attached)
                .append(",\"logger_restored\":").append(restored)
                .append(",\"quiescent\":").append(OWNED.stream().noneMatch(Thread::isAlive))
                .append(",\"phases_completed\":").append(completed).append(",\"connections\":").append(OWNED.size())
                .append(",\"qop\":\"").append(OWNED.isEmpty() ? "not_observed" : "auth-conf")
                .append("\",\"phase_connections\":[");
            for (int i = 0; i < 10; i++) { if (i > 0) text.append(','); text.append(COUNTS[i]); }
            return text.append("]}").toString();
        }
    }
}
