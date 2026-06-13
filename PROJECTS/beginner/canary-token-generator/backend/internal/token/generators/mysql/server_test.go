// ©AngelaMos | 2026
// server_test.go

package mysql_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/mysql"
)

type stubHandler struct {
	called       atomic.Int32
	lastCloseErr atomic.Value
	closed       chan struct{}
	once         sync.Once
}

func newStubHandler() *stubHandler {
	return &stubHandler{closed: make(chan struct{})}
}

func (s *stubHandler) HandleConnection(_ context.Context, conn net.Conn) {
	s.called.Add(1)
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.lastCloseErr.Store(err)
	}
	s.once.Do(func() { close(s.closed) })
}

func dialOnce(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	if cErr := conn.Close(); cErr != nil && !errors.Is(cErr, net.ErrClosed) {
		return cErr
	}
	return nil
}

func runServer(
	t *testing.T,
	ctx context.Context,
	h mysql.ConnectionHandler,
) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())

	done := make(chan error, 1)
	go func() {
		done <- mysql.Run(ctx, addr, h)
	}()

	require.Eventually(t, func() bool {
		return dialOnce(addr) == nil
	}, 2*time.Second, 25*time.Millisecond, "server must accept on %s", addr)

	return addr, done
}

func TestRun_NilHandlerReturnsError(t *testing.T) {
	err := mysql.Run(context.Background(), "127.0.0.1:0", nil)
	require.Error(t, err)
}

func TestRun_AcceptsConnectionAndDispatchesToHandler(t *testing.T) {
	h := newStubHandler()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr, done := runServer(t, ctx, h)
	before := h.called.Load()

	require.NoError(t, dialOnce(addr))

	require.Eventually(t, func() bool {
		return h.called.Load() > before
	}, 2*time.Second, 25*time.Millisecond,
		"single dial must dispatch to handler")

	cancel()
	require.NoError(t, <-done)
}

func TestRun_HandlesMultipleConcurrentConnections(t *testing.T) {
	h := newStubHandler()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr, done := runServer(t, ctx, h)
	before := h.called.Load()

	const n = 10
	results := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- dialOnce(addr)
		}()
	}
	wg.Wait()
	close(results)

	for err := range results {
		require.NoError(t, err)
	}

	require.Eventually(t, func() bool {
		return h.called.Load() >= before+int32(n)
	}, 2*time.Second, 25*time.Millisecond,
		"all %d connections must be dispatched", n)

	cancel()
	require.NoError(t, <-done)
}

func TestRun_ContextCancellationStopsListenerCleanly(t *testing.T) {
	h := newStubHandler()
	ctx, cancel := context.WithCancel(context.Background())

	addr, done := runServer(t, ctx, h)
	require.NoError(t, dialOnce(addr))
	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s after context cancellation")
	}

	_, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
	require.Error(t, err, "listener must be closed after context cancellation")
}

func TestRun_InvalidAddressReturnsError(t *testing.T) {
	err := mysql.Run(
		context.Background(),
		"not-a-valid-addr:not-a-port",
		newStubHandler(),
	)
	require.Error(t, err)
}
