// ©AngelaMos | 2026
// server.go

package mysql

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	acceptShutdownGrace = 2 * time.Second
	tcpNetwork          = "tcp"
)

type ConnectionHandler interface {
	HandleConnection(ctx context.Context, conn net.Conn)
}

func Run(
	ctx context.Context,
	addr string,
	h ConnectionHandler,
) error {
	if h == nil {
		return fmt.Errorf("mysql: nil connection handler")
	}
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, tcpNetwork, addr)
	if err != nil {
		return fmt.Errorf("mysql: listen %s: %w", addr, err)
	}
	defer func() {
		if cErr := listener.Close(); cErr != nil &&
			!errors.Is(cErr, net.ErrClosed) {
			slog.WarnContext(ctx, "mysql: close listener", "error", cErr)
		}
	}()

	slog.InfoContext(
		ctx,
		"mysql: listener started",
		"addr",
		listener.Addr().String(),
	)

	go func() {
		<-ctx.Done()
		if cErr := listener.Close(); cErr != nil &&
			!errors.Is(cErr, net.ErrClosed) {
			slog.WarnContext(
				ctx,
				"mysql: shutdown close listener",
				"error",
				cErr,
			)
		}
	}()

	var wg sync.WaitGroup
	for {
		conn, aErr := listener.Accept()
		if aErr != nil {
			if errors.Is(ctx.Err(), context.Canceled) ||
				errors.Is(aErr, net.ErrClosed) {
				wg.Wait()
				return nil
			}
			slog.WarnContext(ctx, "mysql: accept", "error", aErr)
			continue
		}

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			h.HandleConnection(ctx, c)
		}(conn)
	}
}
