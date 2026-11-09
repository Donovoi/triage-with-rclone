package rpc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

type contextTestTransport struct {
	write func(io.Writer) error
	read func(io.Reader) error
}

func (t contextTestTransport) writeRequest(w io.Writer, _ string, _ int32, _ proto.Message) error {
	if t.write != nil {
		return t.write(w)
	}
	return nil
}

func (t contextTestTransport) readResponse(r io.Reader, _ string, _ int32, _ proto.Message) error {
	if t.read != nil {
		return t.read(r)
	}
	return nil
}

func contextTestWait(t *testing.T, done <-chan error, want error) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("result %v, want %v", err, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("operation did not finish")
	}
}

func contextTestEntered(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("operation did not reach the held boundary")
	}
}

func contextTestCall(c *NamenodeConnection, ctx context.Context) <-chan error {
	done := make(chan error, 1)
	go func() { done <- c.ExecuteContext(ctx, "test", nil, nil) }()
	return done
}

func TestContextAdmissionCancellationPreservesOwner(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	entered := make(chan struct{})
	c := &NamenodeConnection{conn: client, transport: contextTestTransport{read: func(r io.Reader) error {
		close(entered)
		_, err := io.ReadFull(r, make([]byte, 1))
		return err
	}}}
	owner, cancelOwner := context.WithTimeout(context.Background(), 2 * time.Second)
	defer cancelOwner()
	ownerDone := contextTestCall(c, owner)
	contextTestEntered(t, entered)
	ctx, cancel := context.WithCancel(context.Background())
	done := contextTestCall(c, ctx)
	cancel()
	contextTestWait(t, done, context.Canceled)
	if _, err := peer.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	contextTestWait(t, ownerDone, nil)
	if c.conn != client || c.currentRequestID != 1 {
		t.Fatal("queued cancellation changed or interrupted the owning request")
	}
}

func TestContextPrecancelledRequestHasNoEffects(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	c := &NamenodeConnection{conn: client}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.ExecuteContext(ctx, "test", nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if c.conn != client || c.currentRequestID != 0 {
		t.Fatal("pre-cancelled request touched connection state")
	}
}

func TestContextExpiredDeadlineHasNoEffects(t *testing.T) {
	c := &NamenodeConnection{}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := c.ExecuteContext(ctx, "test", nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if c.currentRequestID != 0 {
		t.Fatal("expired request was admitted")
	}
}

func TestContextHeldResponseFinishesBeforeRelease(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	entered := make(chan struct{})
	c := &NamenodeConnection{
		conn: client,
		host: &namenodeHost{},
		transport: contextTestTransport{read: func(r io.Reader) error {
			close(entered)
			_, err := io.ReadFull(r, make([]byte, 1))
			return err
		}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := contextTestCall(c, ctx)
	contextTestEntered(t, entered)
	cancel()
	contextTestWait(t, done, context.Canceled)
	if c.conn != nil || !c.host.lastErrorAt.IsZero() || c.host.lastError != nil {
		t.Fatal("cancelled stream remained reusable or imposed host backoff")
	}
	if _, err := peer.Write([]byte{1}); err == nil {
		t.Fatal("response could still be released on cancelled stream")
	}
}

func TestContextBlockedWriteFinishes(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	entered := make(chan struct{})
	c := &NamenodeConnection{conn: client, transport: contextTestTransport{
		write: func(w io.Writer) error {
			close(entered)
			_, err := w.Write([]byte{1})
			return err
		},
		read: func(io.Reader) error { return errors.New("read must not start") },
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := contextTestCall(c, ctx)
	contextTestEntered(t, entered)
	cancel()
	contextTestWait(t, done, context.Canceled)
	if c.conn != nil {
		t.Fatal("partially written stream remained reusable")
	}
}

func TestContextDialReceivesCancellation(t *testing.T) {
	entered := make(chan struct{})
	c := &NamenodeConnection{
		hostList: []*namenodeHost{{address: "fixture"}},
		dialFunc: func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := contextTestCall(c, ctx)
	contextTestEntered(t, entered)
	cancel()
	contextTestWait(t, done, context.Canceled)
	if c.conn != nil || !c.host.lastErrorAt.IsZero() {
		t.Fatal("cancelled dial retained a stream or imposed host backoff")
	}
}

type contextWriteSignalConn struct {
	net.Conn
	once sync.Once
	entered chan struct{}
}

func (c *contextWriteSignalConn) Write(b []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Write(b)
}

func TestContextHandshakeReceivesCancellation(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	entered := make(chan struct{})
	wrapped := &contextWriteSignalConn{Conn: client, entered: entered}
	c := &NamenodeConnection{
		hostList: []*namenodeHost{{address: "fixture"}},
		dialFunc: func(context.Context, string, string) (net.Conn, error) { return wrapped, nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := contextTestCall(c, ctx)
	contextTestEntered(t, entered)
	cancel()
	contextTestWait(t, done, context.Canceled)
	if c.conn != nil || !c.host.lastErrorAt.IsZero() {
		t.Fatal("cancelled handshake retained a stream or imposed host backoff")
	}
}

func TestContextCompletedRequestCannotCloseNextOperation(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	c := &NamenodeConnection{conn: client, transport: contextTestTransport{}}
	first, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	if err := c.ExecuteContext(first, "first", nil, nil); err != nil {
		t.Fatal(err)
	}
	cancelFirst()
	entered := make(chan struct{})
	c.transport = contextTestTransport{read: func(r io.Reader) error {
		close(entered)
		_, err := io.ReadFull(r, make([]byte, 1))
		return err
	}}
	next, cancelNext := context.WithTimeout(context.Background(), 2 * time.Second)
	defer cancelNext()
	done := contextTestCall(c, next)
	contextTestEntered(t, entered)
	if _, err := peer.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	contextTestWait(t, done, nil)
	if c.conn != client {
		t.Fatal("completed request invalidated later operation")
	}
}

type contextHeldCloseConn struct {
	net.Conn
	once sync.Once
	entered chan struct{}
	release <-chan struct{}
}

func (c *contextHeldCloseConn) Close() error {
	c.once.Do(func() {
		_ = c.Conn.Close()
		close(c.entered)
		<-c.release
	})
	return nil
}

func TestContextStartedCallbackIsJoinedBeforeReturn(t *testing.T) {
	client, peer := net.Pipe()
	entered := make(chan struct{})
	readDone := make(chan struct{})
	closeEntered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseClose := func() { releaseOnce.Do(func() { close(release) }) }
	wrapped := &contextHeldCloseConn{Conn: client, entered: closeEntered, release: release}
	t.Cleanup(func() { releaseClose(); _ = client.Close(); _ = peer.Close() })
	c := &NamenodeConnection{conn: wrapped, transport: contextTestTransport{read: func(r io.Reader) error {
		close(entered)
		_, err := io.ReadFull(r, make([]byte, 1))
		close(readDone)
		return err
	}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := contextTestCall(c, ctx)
	contextTestEntered(t, entered)
	cancel()
	contextTestEntered(t, closeEntered)
	contextTestEntered(t, readDone)
	select {
	case <-done:
		t.Fatal("operation returned before the started callback completed")
	case <-time.After(50 * time.Millisecond):
	}
	releaseClose()
	contextTestWait(t, done, context.Canceled)
	if c.conn != nil {
		t.Fatal("cancelled connection remained installed")
	}
}

func TestContextNonCancellationErrorIsPreserved(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	want := errors.New("fixture read error")
	c := &NamenodeConnection{conn: client, transport: contextTestTransport{
		read: func(io.Reader) error { return want },
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.ExecuteContext(ctx, "test", nil, nil); !errors.Is(err, want) {
		t.Fatal(err)
	}
	if c.conn != client {
		t.Fatal("non-cancellation behavior changed")
	}
}

func TestContextCancelledStreamRequiresFreshDial(t *testing.T) {
	firstClient, firstPeer := net.Pipe()
	defer firstClient.Close()
	defer firstPeer.Close()
	secondClient, secondPeer := net.Pipe()
	defer secondClient.Close()
	defer secondPeer.Close()
	entered := make(chan struct{})
	host := &namenodeHost{address: "fixture"}
	c := &NamenodeConnection{
		ClientID: []byte("context-fixture1"), User: "fixture",
		conn: firstClient, host: host, hostList: []*namenodeHost{host},
		transport: contextTestTransport{read: func(r io.Reader) error {
			close(entered)
			_, err := io.ReadFull(r, make([]byte, 1))
			return err
		}},
	}
	first, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	firstDone := contextTestCall(c, first)
	contextTestEntered(t, entered)
	cancelFirst()
	contextTestWait(t, firstDone, context.Canceled)
	dialled := false
	c.dialFunc = func(context.Context, string, string) (net.Conn, error) {
		if dialled {
			return nil, errors.New("unexpected extra dial")
		}
		dialled = true
		return secondClient, nil
	}
	c.transport = contextTestTransport{}
	packet, err := makeRPCPacket(newRPCRequestHeader(handshakeCallID, c.ClientID), newConnectionContext(c.User, c.kerberosRealm))
	if err != nil {
		t.Fatal(err)
	}
	expected := append([]byte{'h', 'r', 'p', 'c', rpcVersion, serviceClass, noneAuthProtocol}, packet...)
	handshakeRead := make(chan error, 1)
	go func() {
		received := make([]byte, len(expected))
		_, err := io.ReadFull(secondPeer, received)
		if err == nil && !bytes.Equal(received, expected) {
			err = errors.New("fresh handshake did not match expected framing")
		}
		handshakeRead <- err
	}()
	next, cancelNext := context.WithTimeout(context.Background(), 2 * time.Second)
	defer cancelNext()
	contextTestWait(t, contextTestCall(c, next), nil)
	contextTestWait(t, handshakeRead, nil)
	if !dialled || c.conn != secondClient {
		t.Fatal("next operation did not acquire a fresh connection")
	}
}
