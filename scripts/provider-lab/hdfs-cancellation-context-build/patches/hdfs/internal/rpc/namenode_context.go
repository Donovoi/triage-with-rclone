package rpc

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
)

// contextMutex preserves exclusive ownership while allowing a queued request
// to leave without starting a goroutine that may remain blocked on a mutex.
type contextMutex struct {
	once sync.Once
	token chan struct{}
}

func (m *contextMutex) LockContext(ctx context.Context) error {
	m.once.Do(func() { m.token = make(chan struct{}, 1) })
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case m.token <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-m.token
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *contextMutex) Lock() {
	_ = m.LockContext(context.Background())
}

func (m *contextMutex) Unlock() {
	<-m.token
}

// withConnectionContext is called with reqLock held. The callback captures the
// exact owned connection; it never reads or mutates c.conn. A started callback
// is joined before c.conn changes or another request can acquire reqLock.
// Cancellation discards the stream because a partial RPC frame cannot be reused.
func (c *NamenodeConnection) withConnectionContext(ctx context.Context, conn net.Conn, operation func() error) (err error) {
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		c.conn = nil
		return err
	}
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
		close(finished)
	})
	defer func() {
		if !stop() {
			<-finished
		}
		if contextErr := ctx.Err(); contextErr != nil {
			_ = conn.Close()
			c.conn = nil
			err = contextErr
		}
	}()
	return operation()
}

func (c *NamenodeConnection) resolveConnectionContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.conn != nil {
		return nil
	}
	var lastError error
	if c.host != nil {
		lastError = c.host.lastError
	}
	for _, host := range c.hostList {
		if err := ctx.Err(); err != nil {
			return err
		}
		if time.Since(host.lastErrorAt) < backoffDuration {
			continue
		}
		if c.dialFunc == nil {
			c.dialFunc = (&net.Dialer{}).DialContext
		}
		c.host = host
		conn, err := c.dialFunc(ctx, "tcp", host.address)
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			if contextErr := ctx.Err(); contextErr != nil {
				return contextErr
			}
			c.markFailure(err)
			lastError = err
			continue
		}
		c.conn = conn
		err = c.withConnectionContext(ctx, conn, c.doNamenodeHandshake)
		if err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return contextErr
			}
			c.markFailure(err)
			lastError = err
			continue
		}
		return nil
	}
	return fmt.Errorf("no available namenodes: %s", lastError)
}

// ExecuteContext performs one RPC with context-aware admission, connection,
// handshake, write and response read. Existing Execute callers keep their
// background-context behavior; a cancelled operation never reuses its stream.
func (c *NamenodeConnection) ExecuteContext(ctx context.Context, method string, req proto.Message, resp proto.Message) error {
	if err := c.reqLock.LockContext(ctx); err != nil {
		return err
	}
	defer c.reqLock.Unlock()

	c.currentRequestID++
	requestID := c.currentRequestID
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.resolveConnectionContext(ctx); err != nil {
			return err
		}
		conn := c.conn
		writeFailed := false
		err := c.withConnectionContext(ctx, conn, func() error {
			if err := c.transport.writeRequest(conn, method, requestID, req); err != nil {
				writeFailed = true
				return err
			}
			return c.transport.readResponse(conn, method, requestID, resp)
		})
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		if err != nil {
			if writeFailed {
				c.markFailure(err)
				continue
			}
			if nerr, ok := err.(*NamenodeError); ok && nerr.exception == standbyExceptionClass {
				c.markFailure(err)
				continue
			}
			return err
		}
		return nil
	}
}
