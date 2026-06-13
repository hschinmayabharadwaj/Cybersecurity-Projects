// ©AngelaMos | 2026
// handler_test.go

package mysql_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/mysql"
)

func closeQuietly(t *testing.T, closers ...io.Closer) {
	t.Helper()
	for _, c := range closers {
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("close: %v", err)
		}
	}
}

type fakeTokenLookup struct {
	tokens map[string]*token.Token
	err    error
	calls  int32
}

func (f *fakeTokenLookup) GetByID(
	_ context.Context,
	id string,
) (*token.Token, error) {
	atomic.AddInt32(&f.calls, 1)
	if f.err != nil {
		return nil, f.err
	}
	tok, ok := f.tokens[id]
	if !ok {
		return nil, nil
	}
	return tok, nil
}

type fakeEventRecorder struct {
	mu     sync.Mutex
	events []*event.Event
	err    error
}

func (f *fakeEventRecorder) Record(
	_ context.Context,
	_ *token.Token,
	evt *event.Event,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, evt)
	return nil
}

func (f *fakeEventRecorder) snapshot() []*event.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*event.Event, len(f.events))
	copy(out, f.events)
	return out
}

func newConnPair(t *testing.T) (clientSide, serverSide net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, listener.Close())
	}()

	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, aErr := listener.Accept()
		ch <- accepted{conn: c, err: aErr}
	}()

	dialed, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	a := <-ch
	require.NoError(t, a.err)
	return dialed, a.conn
}

func buildHandshakeResponse41ForHandler(t *testing.T, username string) []byte {
	t.Helper()
	var payload bytes.Buffer
	var caps [4]byte
	binary.LittleEndian.PutUint32(caps[:], 0x0001a285)
	payload.Write(caps[:])
	var maxPkt [4]byte
	binary.LittleEndian.PutUint32(maxPkt[:], 0x01000000)
	payload.Write(maxPkt[:])
	payload.WriteByte(0x21)
	var filler [23]byte
	payload.Write(filler[:])
	payload.WriteString(username)
	payload.WriteByte(0x00)
	body := payload.Bytes()
	out := make([]byte, 4+len(body))
	n := len(body)
	out[0] = byte(n & 0xff)
	out[1] = byte((n >> 8) & 0xff)
	out[2] = byte((n >> 16) & 0xff)
	out[3] = 0x01
	copy(out[4:], body)
	return out
}

func readAllAvailable(t *testing.T, conn net.Conn, want int) []byte {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, want)
	total := 0
	for total < want {
		n, err := conn.Read(buf[total:])
		if err != nil {
			break
		}
		total += n
	}
	return buf[:total]
}

func TestHandleConnection_WritesHandshakeFirst(t *testing.T) {
	client, server := newConnPair(t)
	t.Cleanup(func() { closeQuietly(t, client, server) })

	h := mysql.NewHandler(
		&fakeTokenLookup{tokens: map[string]*token.Token{}},
		&fakeEventRecorder{},
	)

	done := make(chan struct{})
	go func() {
		h.HandleConnection(context.Background(), server)
		close(done)
	}()

	got := readAllAvailable(t, client, 80)
	require.NotEmpty(t, got)
	require.Equal(t, byte(0x00), got[3], "handshake sequence ID 0")
	require.Equal(t, byte(0x0a), got[4], "protocol version 10")
	require.Contains(t, string(got), "5.7.40-canary")

	require.NoError(t, client.Close())
	<-done
}

func TestHandleConnection_NonCanaryUsernameDropsSilently(t *testing.T) {
	client, server := newConnPair(t)
	t.Cleanup(func() { closeQuietly(t, client, server) })

	tok := &token.Token{ID: "abc", Type: token.TypeMySQL}
	lookup := &fakeTokenLookup{tokens: map[string]*token.Token{"abc": tok}}
	rec := &fakeEventRecorder{}
	h := mysql.NewHandler(lookup, rec)

	done := make(chan struct{})
	go func() {
		h.HandleConnection(context.Background(), server)
		close(done)
	}()

	_ = readAllAvailable(t, client, 80)
	pkt := buildHandshakeResponse41ForHandler(t, "regular_user")
	_, err := client.Write(pkt)
	require.NoError(t, err)

	<-done
	require.Empty(
		t,
		rec.snapshot(),
		"non-canary_-prefixed username must not produce an event",
	)
}

func TestHandleConnection_KnownTokenRecordsEventAndSendsErr(t *testing.T) {
	client, server := newConnPair(t)
	t.Cleanup(func() { closeQuietly(t, client, server) })

	tok := &token.Token{ID: "mytoken", Type: token.TypeMySQL}
	lookup := &fakeTokenLookup{
		tokens: map[string]*token.Token{"mytoken": tok},
	}
	rec := &fakeEventRecorder{}
	h := mysql.NewHandler(lookup, rec)

	done := make(chan struct{})
	go func() {
		h.HandleConnection(context.Background(), server)
		close(done)
	}()

	_ = readAllAvailable(t, client, 80)
	pkt := buildHandshakeResponse41ForHandler(t, "canary_mytoken")
	_, err := client.Write(pkt)
	require.NoError(t, err)

	errPkt := readAllAvailable(t, client, 200)
	require.NotEmpty(t, errPkt)
	require.Contains(
		t,
		string(errPkt),
		`Access denied for user 'canary_mytoken'`,
	)
	require.Contains(t, string(errPkt), "28000")

	<-done

	events := rec.snapshot()
	require.Len(t, events, 1)
	require.Equal(t, "mytoken", events[0].TokenID)
	require.NotEmpty(
		t,
		events[0].SourceIP,
		"source IP must be captured from RemoteAddr",
	)
}

func TestHandleConnection_EventExtraContainsKubectlEquivalentFields(
	t *testing.T,
) {
	client, server := newConnPair(t)
	t.Cleanup(func() { closeQuietly(t, client, server) })

	tok := &token.Token{ID: "extra-probe", Type: token.TypeMySQL}
	lookup := &fakeTokenLookup{
		tokens: map[string]*token.Token{"extra-probe": tok},
	}
	rec := &fakeEventRecorder{}
	h := mysql.NewHandler(lookup, rec)

	done := make(chan struct{})
	go func() {
		h.HandleConnection(context.Background(), server)
		close(done)
	}()

	_ = readAllAvailable(t, client, 80)
	_, err := client.Write(
		buildHandshakeResponse41ForHandler(t, "canary_extra-probe"),
	)
	require.NoError(t, err)
	_ = readAllAvailable(t, client, 200)
	<-done

	events := rec.snapshot()
	require.Len(t, events, 1)
	require.NotEmpty(t, events[0].Extra)

	var extra map[string]any
	require.NoError(t, json.Unmarshal(events[0].Extra, &extra))
	require.Equal(t, "canary_extra-probe", extra["mysql_username"])
	require.Equal(
		t,
		"0x0001a285",
		extra["mysql_client_capabilities"],
		"capabilities formatted as 0x + 8 hex digits",
	)
	charset, ok := extra["mysql_client_charset"].(float64)
	require.True(t, ok, "charset must decode as a JSON number")
	require.Equal(t, 0x21, int(charset))
}

func TestHandleConnection_UnknownTokenDoesNotRecordOrErrAdvertise(
	t *testing.T,
) {
	client, server := newConnPair(t)
	t.Cleanup(func() { closeQuietly(t, client, server) })

	lookup := &fakeTokenLookup{tokens: map[string]*token.Token{}}
	rec := &fakeEventRecorder{}
	h := mysql.NewHandler(lookup, rec)

	done := make(chan struct{})
	go func() {
		h.HandleConnection(context.Background(), server)
		close(done)
	}()

	_ = readAllAvailable(t, client, 80)
	_, err := client.Write(
		buildHandshakeResponse41ForHandler(t, "canary_does-not-exist"),
	)
	require.NoError(t, err)
	<-done

	require.Empty(t, rec.snapshot(), "unknown token must not record an event")
}

func TestHandleConnection_LookupErrorIsSilent(t *testing.T) {
	client, server := newConnPair(t)
	t.Cleanup(func() { closeQuietly(t, client, server) })

	lookup := &fakeTokenLookup{err: errors.New("db down")}
	rec := &fakeEventRecorder{}
	h := mysql.NewHandler(lookup, rec)

	done := make(chan struct{})
	go func() {
		h.HandleConnection(context.Background(), server)
		close(done)
	}()

	_ = readAllAvailable(t, client, 80)
	_, err := client.Write(
		buildHandshakeResponse41ForHandler(t, "canary_anything"),
	)
	require.NoError(t, err)
	<-done

	require.Empty(t, rec.snapshot())
}

func TestHandleConnection_NilEventRecorderTolerated(t *testing.T) {
	client, server := newConnPair(t)
	t.Cleanup(func() { closeQuietly(t, client, server) })

	tok := &token.Token{ID: "noevents", Type: token.TypeMySQL}
	lookup := &fakeTokenLookup{tokens: map[string]*token.Token{"noevents": tok}}
	h := mysql.NewHandler(lookup, nil)

	done := make(chan struct{})
	go func() {
		h.HandleConnection(context.Background(), server)
		close(done)
	}()

	_ = readAllAvailable(t, client, 80)
	_, err := client.Write(
		buildHandshakeResponse41ForHandler(t, "canary_noevents"),
	)
	require.NoError(t, err)

	errPkt := readAllAvailable(t, client, 200)
	require.NotEmpty(
		t,
		errPkt,
		"ERR packet still sent even without recorder wired",
	)
	<-done
}

func TestHandleConnection_BadAuthPacketDropsSilently(t *testing.T) {
	client, server := newConnPair(t)
	t.Cleanup(func() { closeQuietly(t, client, server) })

	rec := &fakeEventRecorder{}
	h := mysql.NewHandler(&fakeTokenLookup{}, rec)

	done := make(chan struct{})
	go func() {
		h.HandleConnection(context.Background(), server)
		close(done)
	}()

	_ = readAllAvailable(t, client, 80)
	_, err := client.Write([]byte{0x00, 0x00, 0x00, 0x01})
	require.NoError(t, err)
	<-done

	require.Empty(t, rec.snapshot())
}
