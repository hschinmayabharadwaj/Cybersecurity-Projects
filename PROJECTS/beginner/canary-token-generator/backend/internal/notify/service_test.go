// ©AngelaMos | 2026
// service_test.go

package notify_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/notify"
)

type fakeSender struct {
	channel    string
	calls      atomic.Int32
	returnErr  error
	lastInfo   atomic.Value
	delay      time.Duration
	respectCtx bool
}

func (f *fakeSender) Channel() string { return f.channel }

func (f *fakeSender) Send(
	ctx context.Context,
	info event.NotifyInfo,
	_ *event.Event,
) error {
	f.calls.Add(1)
	f.lastInfo.Store(info)
	if f.delay > 0 {
		if f.respectCtx {
			select {
			case <-time.After(f.delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		} else {
			time.Sleep(f.delay)
		}
	}
	return f.returnErr
}

type fakeStatusWriter struct {
	mu      sync.Mutex
	updates []statusUpdate
	err     error
}

type statusUpdate struct {
	eventID int64
	status  event.NotifyStatus
	sentAt  *time.Time
}

func (f *fakeStatusWriter) UpdateNotifyStatus(
	_ context.Context,
	id int64,
	status event.NotifyStatus,
	sentAt *time.Time,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates = append(
		f.updates,
		statusUpdate{eventID: id, status: status, sentAt: sentAt},
	)
	return f.err
}

func (f *fakeStatusWriter) snapshot() []statusUpdate {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]statusUpdate, len(f.updates))
	copy(out, f.updates)
	return out
}

func sampleEvent(id int64) *event.Event {
	return &event.Event{
		ID:          id,
		TokenID:     "tokfoo000001",
		TriggeredAt: time.Now().UTC(),
		SourceIP:    "203.0.113.1",
	}
}

func sampleInfo(channel string) event.NotifyInfo {
	return event.NotifyInfo{
		TokenID:      "tokfoo000001",
		ManageID:     "abcd",
		Type:         "webbug",
		Memo:         "test",
		AlertChannel: channel,
		TelegramBot:  "bot",
		TelegramChat: "chat",
		WebhookURL:   "https://example.com/h",
	}
}

func newService(
	t *testing.T,
	status notify.StatusWriter,
	senders ...notify.Sender,
) *notify.Service {
	t.Helper()
	svc := notify.NewService(status,
		notify.WithLogger(slog.New(slog.NewTextHandler(testWriter{t}, nil))),
		notify.WithSendTimeout(2*time.Second),
	)
	svc.Register(senders...)
	return svc
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(
	p []byte,
) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

func TestService_RoutesByChannel(t *testing.T) {
	t.Parallel()
	tg := &fakeSender{channel: "telegram"}
	wh := &fakeSender{channel: "webhook"}
	status := &fakeStatusWriter{}
	svc := newService(t, status, tg, wh)

	svc.Notify(sampleInfo("telegram"), sampleEvent(1))
	svc.Notify(sampleInfo("webhook"), sampleEvent(2))
	svc.Wait()

	require.Equal(t, int32(1), tg.calls.Load())
	require.Equal(t, int32(1), wh.calls.Load())
}

func TestService_MarksSentOnSuccess(t *testing.T) {
	t.Parallel()
	tg := &fakeSender{channel: "telegram"}
	status := &fakeStatusWriter{}
	svc := newService(t, status, tg)

	svc.Notify(sampleInfo("telegram"), sampleEvent(1))
	svc.Wait()

	updates := status.snapshot()
	require.Len(t, updates, 1)
	require.Equal(t, int64(1), updates[0].eventID)
	require.Equal(t, event.NotifySent, updates[0].status)
	require.NotNil(t, updates[0].sentAt)
}

func TestService_MarksFailedOnSenderError(t *testing.T) {
	t.Parallel()
	tg := &fakeSender{channel: "telegram", returnErr: errors.New("api blew up")}
	status := &fakeStatusWriter{}
	svc := newService(t, status, tg)

	svc.Notify(sampleInfo("telegram"), sampleEvent(7))
	svc.Wait()

	updates := status.snapshot()
	require.Len(t, updates, 1)
	require.Equal(t, int64(7), updates[0].eventID)
	require.Equal(t, event.NotifyFailed, updates[0].status)
	require.Nil(t, updates[0].sentAt)
}

func TestService_MarksFailedWhenChannelUnknown(t *testing.T) {
	t.Parallel()
	tg := &fakeSender{channel: "telegram"}
	status := &fakeStatusWriter{}
	svc := newService(t, status, tg)

	svc.Notify(sampleInfo("smoke-signal"), sampleEvent(99))
	svc.Wait()

	require.Equal(t, int32(0), tg.calls.Load())
	updates := status.snapshot()
	require.Len(t, updates, 1)
	require.Equal(t, event.NotifyFailed, updates[0].status)
}

func TestService_NotifyIsAsync(t *testing.T) {
	t.Parallel()
	tg := &fakeSender{channel: "telegram", delay: 100 * time.Millisecond}
	status := &fakeStatusWriter{}
	svc := newService(t, status, tg)

	start := time.Now()
	svc.Notify(sampleInfo("telegram"), sampleEvent(1))
	require.Less(t, time.Since(start), 50*time.Millisecond,
		"Notify should return immediately, not wait for the send")
	svc.Wait()
	require.Equal(t, int32(1), tg.calls.Load())
}

func TestService_DispatchTimeoutBoundsSender(t *testing.T) {
	t.Parallel()
	tg := &fakeSender{
		channel:    "telegram",
		delay:      2 * time.Second,
		respectCtx: true,
	}
	status := &fakeStatusWriter{}
	svc := notify.NewService(status,
		notify.WithSendTimeout(50*time.Millisecond),
	)
	svc.Register(tg)

	svc.Notify(sampleInfo("telegram"), sampleEvent(1))
	svc.Wait()

	updates := status.snapshot()
	require.Len(t, updates, 1)
	require.Equal(t, event.NotifyFailed, updates[0].status,
		"timeout should mark event failed")
}

func TestService_StatusWriterErrorDoesNotPanic(t *testing.T) {
	t.Parallel()
	tg := &fakeSender{channel: "telegram"}
	status := &fakeStatusWriter{err: errors.New("db down")}
	svc := newService(t, status, tg)

	require.NotPanics(t, func() {
		svc.Notify(sampleInfo("telegram"), sampleEvent(1))
		svc.Wait()
	})
}

func TestService_ConcurrentNotifyAllComplete(t *testing.T) {
	t.Parallel()
	tg := &fakeSender{channel: "telegram", delay: 10 * time.Millisecond}
	status := &fakeStatusWriter{}
	svc := newService(t, status, tg)

	const n = 50
	for i := range n {
		svc.Notify(sampleInfo("telegram"), sampleEvent(int64(i+1)))
	}
	svc.Wait()
	require.Equal(t, int32(n), tg.calls.Load())
	require.Len(t, status.snapshot(), n)
}
