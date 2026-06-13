// ©AngelaMos | 2026
// handler.go

package mysql

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
)

const (
	connectionDeadline = 10 * time.Second

	mysqlUsernamePrefix = "canary_"

	extraMySQLUsername     = "mysql_username"
	extraMySQLCapabilities = "mysql_client_capabilities"
	extraMySQLCharset      = "mysql_client_charset"

	capabilitiesFormat = "0x%08x"
)

type TokenLookup interface {
	GetByID(ctx context.Context, id string) (*token.Token, error)
}

type EventRecorder interface {
	Record(ctx context.Context, t *token.Token, evt *event.Event) error
}

type Handler struct {
	tokens TokenLookup
	events EventRecorder
}

func NewHandler(tokens TokenLookup, events EventRecorder) *Handler {
	return &Handler{tokens: tokens, events: events}
}

func (h *Handler) HandleConnection(ctx context.Context, conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			slog.WarnContext(ctx, "mysql: close connection", "error", err)
		}
	}()

	if err := conn.SetDeadline(time.Now().Add(connectionDeadline)); err != nil {
		slog.WarnContext(ctx, "mysql: set deadline", "error", err)
		return
	}

	if err := h.writeHandshake(conn); err != nil {
		return
	}

	auth, err := ReadClientAuth(conn)
	if err != nil {
		return
	}

	if !strings.HasPrefix(auth.Username, mysqlUsernamePrefix) {
		return
	}
	tokenID := strings.TrimPrefix(auth.Username, mysqlUsernamePrefix)

	tok, err := h.tokens.GetByID(ctx, tokenID)
	if err != nil || tok == nil {
		return
	}

	sourceHost := remoteHost(conn)

	if h.events != nil {
		if recErr := h.recordEvent(ctx, tok, sourceHost, auth); recErr != nil {
			slog.WarnContext(
				ctx,
				"mysql: record event",
				"error", recErr,
				"token_id", tok.ID,
			)
		}
	}

	if wErr := h.writeAccessDenied(
		conn,
		auth.Username,
		sourceHost,
	); wErr != nil {
		slog.WarnContext(
			ctx,
			"mysql: write err packet",
			"error", wErr,
			"token_id", tok.ID,
		)
	}
}

func (h *Handler) writeHandshake(conn net.Conn) error {
	connID, err := NewRandomConnectionID()
	if err != nil {
		return fmt.Errorf("connection id: %w", err)
	}
	authData, err := NewRandomAuthData()
	if err != nil {
		return fmt.Errorf("auth data: %w", err)
	}
	pkt, err := BuildHandshakeV10(connID, authData)
	if err != nil {
		return fmt.Errorf("build handshake: %w", err)
	}
	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("write handshake: %w", err)
	}
	return nil
}

func (h *Handler) writeAccessDenied(
	conn net.Conn,
	username, sourceHost string,
) error {
	pkt, err := BuildAccessDeniedErr(username, sourceHost)
	if err != nil {
		return fmt.Errorf("build err packet: %w", err)
	}
	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("write err packet: %w", err)
	}
	return nil
}

func (h *Handler) recordEvent(
	ctx context.Context,
	tok *token.Token,
	sourceHost string,
	auth *ClientAuth,
) error {
	extra, err := buildMySQLExtra(auth)
	if err != nil {
		return fmt.Errorf("build extra: %w", err)
	}
	evt := &event.Event{
		TokenID:  tok.ID,
		SourceIP: sourceHost,
		Extra:    extra,
	}
	if err := h.events.Record(ctx, tok, evt); err != nil {
		return fmt.Errorf("record: %w", err)
	}
	return nil
}

func buildMySQLExtra(auth *ClientAuth) (json.RawMessage, error) {
	extra := map[string]any{
		extraMySQLUsername: auth.Username,
		extraMySQLCapabilities: fmt.Sprintf(
			capabilitiesFormat,
			auth.Capabilities,
		),
		extraMySQLCharset: auth.Charset,
	}
	body, err := json.Marshal(extra)
	if err != nil {
		return nil, fmt.Errorf("marshal mysql extra: %w", err)
	}
	return body, nil
}

func remoteHost(conn net.Conn) string {
	addr := conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
