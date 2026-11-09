/** Owned response state only. The caller proves job identity and terminal
 * cancellation before authorizing discard; this helper exports no raw frames. */
final class HdfsContextHeldResponse implements AutoCloseable {
    enum Action { FORWARD, RELEASED, DISCARD }
    private HdfsCancellationRpcGate.Request pending;
    private int requests, responses, lastPositive, cases, heldCount;
    private int releasedCount, forwardedCount, discardedCount;
    private boolean armed, held, released, discardAuthorized, discardReturned;
    private boolean cancelledClientEof, closed;
    private long deadline, heldAt;

    private static void require(boolean value) throws HdfsCancellationRpcGate.Rejected {
        if (!value) throw new HdfsCancellationRpcGate.Rejected();
    }
    private void awaitChange() throws Exception {
        long left = deadline - System.nanoTime(); require(left > 0);
        wait(Math.max(1, Math.min(50, java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(left))));
    }
    synchronized void request(byte[] frame) throws Exception {
        require(!closed && !cancelledClientEof && !discardAuthorized && ++requests <= 64);
        var value = HdfsCancellationRpcGate.request(frame);
        boolean transferred = false;
        try {
            if (value.kind != HdfsCancellationRpcGate.Kind.CONTROL) {
                require(pending == null && value.callId > lastPositive);
                lastPositive = value.callId; pending = value; transferred = true;
            }
        } finally { if (!transferred) value.close(); }
    }
    synchronized Action response(byte[] frame) throws Exception {
        require(!closed && ++responses <= 64);
        int call = HdfsCancellationRpcGate.responseCallId(frame);
        if (call < 0) {
            require(call == -33 && pending == null && !held);
            return Action.FORWARD;
        }
        require(pending != null && pending.callId == call && !held);
        boolean selected = armed && pending.kind == HdfsCancellationRpcGate.Kind.LISTING;
        Action action = Action.FORWARD;
        if (selected) {
            HdfsCancellationRpcGate.matchingEmptyListingResponse(frame, pending);
            require(!released && !discardAuthorized && !discardReturned && !cancelledClientEof
                && heldCount == releasedCount && releasedCount == forwardedCount && discardedCount == 0);
            held = true; armed = false; heldCount++; heldAt = System.nanoTime(); notifyAll();
            while (!released && !discardAuthorized && !closed) awaitChange();
            require(!closed && System.nanoTime() < deadline);
            if (discardAuthorized) {
                require(!released && cancelledClientEof && cases == 2 && forwardedCount == 1);
                discardReturned = true; action = Action.DISCARD;
            } else {
                require(released && !cancelledClientEof);
                action = Action.RELEASED;
            }
        }
        pending.close(); pending = null; notifyAll();
        return action;
    }
    synchronized void forwarded() throws Exception {
        require(!closed && held && released && !cancelledClientEof && !discardAuthorized
            && !discardReturned && forwardedCount + 1 == releasedCount);
        forwardedCount++; held = false; released = false; notifyAll();
    }
    synchronized void arm(long until) throws Exception {
        require(!closed && !armed && !held && !released && !discardAuthorized && !discardReturned
            && !cancelledClientEof && discardedCount == 0 && cases < 2 && cases == forwardedCount
            && until > System.nanoTime());
        // A background lease may be in flight; match it before arming a listing.
        deadline = until;
        while (pending != null && !closed) awaitChange();
        require(!closed && pending == null && System.nanoTime() < deadline);
        cases++; armed = true;
    }
    synchronized void awaitHeld() throws Exception {
        while (!held && !closed) awaitChange();
        require(isHeld());
    }
    synchronized boolean isHeld() {
        return !closed && held && !released && !discardAuthorized && !discardReturned
            && pending != null && System.nanoTime() < deadline;
    }
    synchronized long heldNanos() throws Exception {
        require(isHeld()); return System.nanoTime() - heldAt;
    }
    synchronized void release() throws Exception {
        require(isHeld() && !cancelledClientEof && heldCount == releasedCount + 1);
        released = true; releasedCount++; notifyAll();
    }
    synchronized void awaitForwarded() throws Exception {
        while (forwardedCount != cases && !closed) awaitChange();
        require(!closed && forwardedCount == cases && !held && !released
            && discardedCount == 0 && !discardAuthorized && !discardReturned);
    }
    // Called only for EOF at the start of a frame on this connection's client
    // input. Partial-frame EOF, socket exceptions and fixture closes do not count.
    synchronized void clientEof() throws Exception {
        require(!closed);
        if (complete(false)) return; // Normal daemon shutdown after two forwards.
        require(isHeld() && cases == 2 && forwardedCount == 1 && !cancelledClientEof);
        cancelledClientEof = true; notifyAll();
    }
    synchronized boolean clientEofObserved() { return cancelledClientEof; }
    // The caller must first prove the same identified job is terminal with
    // context cancellation while this complete response is still held.
    synchronized void authorizeDiscard() throws Exception {
        require(isHeld() && cancelledClientEof && cases == 2 && heldCount == 2
            && releasedCount == 1 && forwardedCount == 1 && discardedCount == 0);
        discardAuthorized = true; notifyAll();
    }
    // Called by the response pump only after its held byte array is erased.
    synchronized void discarded() throws Exception {
        require(!closed && held && !released && discardAuthorized && discardReturned
            && cancelledClientEof && pending == null && discardedCount == 0
            && cases == 2 && forwardedCount == 1 && releasedCount == 1);
        discardedCount = 1; held = false; discardAuthorized = false; discardReturned = false; notifyAll();
    }
    synchronized void awaitDiscarded() throws Exception {
        while (!complete(true) && !closed) awaitChange();
        require(complete(true));
    }
    synchronized boolean complete(boolean discarded) {
        return cases == 2 && heldCount == 2 && !armed && !held && !released
            && !discardAuthorized && !discardReturned
            && (pending == null || pending.kind == HdfsCancellationRpcGate.Kind.LEASE)
            && (discarded ? releasedCount == 1 && forwardedCount == 1 && discardedCount == 1 && cancelledClientEof
                          : releasedCount == 2 && forwardedCount == 2 && discardedCount == 0 && !cancelledClientEof);
    }
    synchronized boolean clean() { return closed && pending == null; }
    @Override public synchronized void close() {
        closed = true;
        if (pending != null) { pending.close(); pending = null; }
        notifyAll();
    }
}
