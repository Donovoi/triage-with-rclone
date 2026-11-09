/** Owned connection state only: no sockets, job API, raw-body export or acceptance. */
final class HdfsCancellationHeldResponse implements AutoCloseable {
    private HdfsCancellationRpcGate.Request pending;
    private int requests, responses, lastPositive, cases, heldCount, releasedCount, forwardedCount;
    private boolean armed, held, released, closed;
    private long deadline, heldAt;
    private static void require(boolean value) throws HdfsCancellationRpcGate.Rejected {
        if (!value) throw new HdfsCancellationRpcGate.Rejected();
    }
    synchronized void request(byte[] frame) throws Exception {
        require(!closed && ++requests <= 64);
        var value = HdfsCancellationRpcGate.request(frame);
        boolean transferred = false;
        try {
            if (value.kind != HdfsCancellationRpcGate.Kind.CONTROL) {
                require(pending == null && value.callId > lastPositive);
                lastPositive = value.callId; pending = value; transferred = true;
            }
        } finally { if (!transferred) value.close(); }
    }
    synchronized boolean response(byte[] frame) throws Exception {
        require(!closed && ++responses <= 64);
        int call = HdfsCancellationRpcGate.responseCallId(frame);
        if (call < 0) { require(call == -33 && pending == null && !held); return false; }
        require(pending != null && pending.callId == call && !held);
        boolean selected = armed && pending.kind == HdfsCancellationRpcGate.Kind.LISTING;
        if (selected) {
            HdfsCancellationRpcGate.matchingEmptyListingResponse(frame, pending);
            require(!released && heldCount == releasedCount && releasedCount == forwardedCount);
            held = true; armed = false; heldCount++; heldAt = System.nanoTime(); notifyAll();
            while (!released && !closed) {
                long left = deadline - System.nanoTime(); require(left > 0);
                wait(Math.max(1, Math.min(50, java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(left))));
            }
            require(released && !closed && System.nanoTime() < deadline);
        }
        pending.close(); pending = null; notifyAll();
        return selected;
    }
    synchronized void forwarded() throws Exception {
        require(!closed && held && released && forwardedCount + 1 == releasedCount);
        forwardedCount++; held = false; released = false; notifyAll();
    }
    synchronized void arm(long until) throws Exception {
        require(!closed && !armed && !held && !released && cases < 2
            && cases == forwardedCount && until > System.nanoTime());
        // A background lease may already be in flight. Wait for its matched
        // response without confusing it with the listing we will arm next.
        while (pending != null && !closed) {
            long left = until - System.nanoTime(); require(left > 0);
            wait(Math.max(1, Math.min(50, java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(left))));
        }
        require(!closed && pending == null && System.nanoTime() < until);
        deadline = until; cases++; armed = true;
    }
    synchronized void awaitHeld() throws Exception {
        while (!held && !closed) {
            long left = deadline - System.nanoTime(); require(left > 0);
            wait(Math.max(1, Math.min(50, java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(left))));
        }
        require(!closed && held && !released && pending != null);
    }
    synchronized boolean isHeld() {
        return !closed && held && !released && pending != null && System.nanoTime() < deadline;
    }
    synchronized long heldNanos() throws Exception { require(isHeld()); return System.nanoTime() - heldAt; }
    synchronized void release() throws Exception {
        require(isHeld() && heldCount == releasedCount + 1);
        released = true; releasedCount++; notifyAll();
    }
    synchronized void awaitForwarded() throws Exception {
        while (forwardedCount != cases && !closed) {
            long left = deadline - System.nanoTime(); require(left > 0);
            wait(Math.max(1, Math.min(50, java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(left))));
        }
        require(!closed && forwardedCount == cases && !held && !released);
    }
    synchronized boolean complete() {
        return cases == 2 && heldCount == 2 && releasedCount == 2 && forwardedCount == 2
            && !armed && !held && !released
            && (pending == null || pending.kind == HdfsCancellationRpcGate.Kind.LEASE);
    }
    synchronized boolean clean() { return closed && pending == null; }
    @Override public synchronized void close() {
        closed = true;
        if (pending != null) { pending.close(); pending = null; }
        notifyAll();
    }
}
