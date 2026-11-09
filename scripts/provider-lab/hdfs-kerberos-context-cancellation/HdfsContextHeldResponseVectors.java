import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;

/** Native state-machine controls. Run only inside the contained hosted probe. */
final class HdfsContextHeldResponseVectors {
    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static void need(boolean value) {
        if (!value) throw new IllegalStateException("context_gate_vector_failed");
    }
    private static void accept(LinkedHashSet<String> seen, String name, boolean value) {
        need(value && seen.add(name));
    }
    private static void reject(LinkedHashSet<String> seen, String name, Checked call) throws Exception {
        boolean rejected = false;
        try { call.run(); }
        catch (HdfsCancellationRpcGate.Rejected error) {
            need("rpc_gate_frame_rejected".equals(error.getMessage())); rejected = true;
        }
        accept(seen, name, rejected);
    }
    private static byte[] request(int call, boolean listing) {
        need(call > 0 && call < 64);
        byte[] value = HexFormat.of().parseHex(listing
            ? "0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"
            : "0000005a1808021000180e221066697874757265636c69656e743030313f0a0b67657446696c65496e666f122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c180100");
        need(value[9] == 0x18 && value[10] == 0x0e); value[10] = (byte)(call * 2);
        return value;
    }
    private static byte[] response(int call) {
        need(call > 0 && call < 64);
        byte[] value = HexFormat.of().parseHex("0000000a0408071000040a021000");
        need(value[5] == 8 && value[6] == 7); value[6] = (byte)call; return value;
    }
    private static long deadline() { return System.nanoTime() + TimeUnit.SECONDS.toNanos(2); }
    private static final class Held implements AutoCloseable {
        final HdfsContextHeldResponse gate;
        final FutureTask<HdfsContextHeldResponse.Action> task;
        final Thread thread;
        final byte[] frame, before;
        Held(HdfsContextHeldResponse owned, int call, boolean arm) throws Exception {
            gate = owned;
            if (arm) gate.arm(deadline());
            byte[] input = request(call, true);
            try { gate.request(input); } finally { Arrays.fill(input, (byte)0); }
            frame = response(call); before = frame.clone();
            task = new FutureTask<>(() -> gate.response(frame));
            thread = new Thread(task, "owned-context-gate-vector"); thread.setDaemon(true);
            boolean entered = false;
            try { thread.start(); gate.awaitHeld(); entered = true; }
            finally {
                if (!entered) { gate.close(); thread.join(1000); need(!thread.isAlive()); }
            }
        }
        HdfsContextHeldResponse.Action take() throws Exception {
            var result = task.get(1, TimeUnit.SECONDS); need(Arrays.equals(frame, before)); return result;
        }
        boolean rejected() throws Exception {
            try { take(); return false; }
            catch (ExecutionException error) {
                return error.getCause() instanceof HdfsCancellationRpcGate.Rejected;
            }
        }
        void forward() throws Exception {
            gate.release(); need(take() == HdfsContextHeldResponse.Action.RELEASED);
            gate.forwarded(); gate.awaitForwarded();
        }
        @Override public void close() throws Exception {
            if (!task.isDone()) gate.close();
            thread.join(1000); need(!thread.isAlive());
            Arrays.fill(frame, (byte)0); Arrays.fill(before, (byte)0);
        }
    }
    private static void baseline(HdfsContextHeldResponse gate) throws Exception {
        try (var held = new Held(gate, 7, true)) { held.forward(); }
    }
    static int checkAll() throws Exception {
        var seen = new LinkedHashSet<String>();
        try (var gate = new HdfsContextHeldResponse()) {
            reject(seen, "release_without_hold", gate::release);
            reject(seen, "discard_without_hold", gate::authorizeDiscard);
            reject(seen, "forward_ack_without_release", gate::forwarded);
            reject(seen, "discard_ack_without_authority", gate::discarded);
            reject(seen, "eof_without_owned_hold", gate::clientEof);
            reject(seen, "expired_arm", () -> gate.arm(System.nanoTime() - 1));
            reject(seen, "response_without_request", () -> gate.response(response(7)));
            gate.request(request(7, true));
            reject(seen, "second_pending_request", () -> gate.request(request(8, true)));
            reject(seen, "mismatched_response_id", () -> gate.response(response(8)));
            accept(seen, "unarmed_response_passes", gate.response(response(7)) == HdfsContextHeldResponse.Action.FORWARD);
            reject(seen, "duplicate_request_id", () -> gate.request(request(7, true)));
            accept(seen, "unarmed_flow_is_not_completion", !gate.complete(false) && !gate.complete(true));
        }
        try (var gate = new HdfsContextHeldResponse()) {
            gate.close();
            reject(seen, "request_after_close", () -> gate.request(request(7, true)));
            reject(seen, "response_after_close", () -> gate.response(response(7)));
            reject(seen, "arm_after_close", () -> gate.arm(deadline()));
            accept(seen, "empty_close_is_not_completion", gate.clean() && !gate.complete(false) && !gate.complete(true));
        }
        try (var gate = new HdfsContextHeldResponse()) {
            try (var held = new Held(gate, 7, true)) {
                reject(seen, "baseline_eof_rejected", gate::clientEof);
                reject(seen, "baseline_discard_rejected", gate::authorizeDiscard);
                reject(seen, "arm_while_held", () -> gate.arm(deadline()));
                gate.release();
                reject(seen, "duplicate_release", gate::release);
                need(held.take() == HdfsContextHeldResponse.Action.RELEASED);
                gate.forwarded(); gate.awaitForwarded();
                reject(seen, "duplicate_forward_ack", gate::forwarded);
                accept(seen, "one_baseline_is_not_completion", !gate.complete(false) && !gate.complete(true));
            }
            try (var held = new Held(gate, 8, true)) { held.forward(); }
            accept(seen, "two_forwarded_responses_complete", gate.complete(false) && !gate.complete(true));
            reject(seen, "third_case_rejected", () -> gate.arm(deadline()));
            gate.clientEof();
            accept(seen, "normal_shutdown_is_not_cancelled_eof", !gate.clientEofObserved() && gate.complete(false));
        }
        try (var gate = new HdfsContextHeldResponse()) {
            baseline(gate);
            try (var held = new Held(gate, 8, true)) {
                reject(seen, "discard_requires_client_eof", gate::authorizeDiscard);
                reject(seen, "premature_discard_ack", gate::discarded);
                gate.clientEof();
                accept(seen, "client_eof_keeps_response_held", gate.clientEofObserved() && gate.isHeld());
                reject(seen, "duplicate_client_eof", gate::clientEof);
                reject(seen, "release_after_client_eof", gate::release);
                reject(seen, "request_after_client_eof", () -> gate.request(request(9, true)));
                gate.authorizeDiscard();
                reject(seen, "duplicate_discard_authority", gate::authorizeDiscard);
                reject(seen, "release_after_discard_authority", gate::release);
                accept(seen, "held_response_requests_discard", held.take() == HdfsContextHeldResponse.Action.DISCARD);
                accept(seen, "discard_requires_erasure_ack", !gate.complete(true) && !gate.complete(false));
                Arrays.fill(held.frame, (byte)0); gate.discarded(); gate.awaitDiscarded();
                accept(seen, "discard_has_distinct_completion", gate.complete(true) && !gate.complete(false));
                reject(seen, "forward_ack_after_discard", gate::forwarded);
                reject(seen, "duplicate_discard_ack", gate::discarded);
                reject(seen, "arm_after_discard", () -> gate.arm(deadline()));
            }
            gate.close();
            accept(seen, "discard_cleanup_preserves_receipt", gate.clean() && gate.complete(true));
        }
        try (var gate = new HdfsContextHeldResponse()) {
            try (var held = new Held(gate, 7, true)) {
                gate.close();
                accept(seen, "premature_close_unblocks_with_rejection", held.rejected());
                accept(seen, "premature_close_is_not_completion", gate.clean() && !gate.complete(false) && !gate.complete(true));
            }
        }
        try (var gate = new HdfsContextHeldResponse()) {
            gate.arm(deadline()); gate.request(request(7, false));
            accept(seen, "metadata_is_not_selected", gate.response(response(7)) == HdfsContextHeldResponse.Action.FORWARD && !gate.isHeld());
            try (var held = new Held(gate, 8, false)) {
                accept(seen, "listing_after_metadata_is_selected", gate.isHeld()); held.forward();
            }
        }
        need(seen.size() == 44);
        return seen.size();
    }
}
