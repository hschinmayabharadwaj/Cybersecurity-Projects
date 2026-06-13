// ©AngelaMos | 2026
// service.go

package notify

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
)

const (
	defaultSendTimeout = 30 * time.Second
	defaultWorkers     = 8
	defaultQueueSize   = 256
)

type Service struct {
	senders     map[string]Sender
	status      StatusWriter
	logger      *slog.Logger
	sendTimeout time.Duration
	workers     int
	queue       chan dispatchJob
	workerWg    sync.WaitGroup
	jobWg       sync.WaitGroup
	closeOnce   sync.Once
}

type dispatchJob struct {
	info event.NotifyInfo
	evt  *event.Event
}

type Option func(*Service)

func WithLogger(l *slog.Logger) Option {
	return func(s *Service) { s.logger = l }
}

func WithSendTimeout(d time.Duration) Option {
	return func(s *Service) { s.sendTimeout = d }
}

func WithMaxConcurrent(n int) Option {
	return func(s *Service) {
		if n > 0 {
			s.workers = n
		}
	}
}

func WithQueueSize(n int) Option {
	return func(s *Service) {
		if n > 0 {
			s.queue = make(chan dispatchJob, n)
		}
	}
}

func NewService(status StatusWriter, opts ...Option) *Service {
	s := &Service{
		senders:     make(map[string]Sender),
		status:      status,
		logger:      slog.Default(),
		sendTimeout: defaultSendTimeout,
		workers:     defaultWorkers,
	}
	for _, o := range opts {
		o(s)
	}
	if s.queue == nil {
		s.queue = make(chan dispatchJob, defaultQueueSize)
	}
	for range s.workers {
		s.workerWg.Add(1)
		go s.worker()
	}
	return s
}

func (s *Service) Register(senders ...Sender) {
	for _, sender := range senders {
		if sender == nil {
			continue
		}
		s.senders[sender.Channel()] = sender
	}
}

func (s *Service) Notify(info event.NotifyInfo, evt *event.Event) {
	s.jobWg.Add(1)
	select {
	case s.queue <- dispatchJob{info: info, evt: evt}:
	default:
		s.jobWg.Done()
		s.logger.Warn("notify: queue full, dropping",
			"event_id", evt.ID,
			"token_id", info.TokenID,
			"channel", info.AlertChannel,
		)
		s.markStatus(
			context.Background(),
			evt.ID,
			event.NotifyFailed,
			nil,
		)
	}
}

func (s *Service) Wait() {
	s.jobWg.Wait()
}

func (s *Service) Shutdown(ctx context.Context) error {
	s.closeOnce.Do(func() { close(s.queue) })
	done := make(chan struct{})
	go func() {
		s.workerWg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) worker() {
	defer s.workerWg.Done()
	for job := range s.queue {
		s.dispatch(job.info, job.evt)
		s.jobWg.Done()
	}
}

func (s *Service) dispatch(info event.NotifyInfo, evt *event.Event) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		s.sendTimeout,
	)
	defer cancel()

	sender, ok := s.senders[info.AlertChannel]
	if !ok {
		s.logger.WarnContext(ctx, "notify: no sender registered",
			"channel", info.AlertChannel,
			"event_id", evt.ID,
			"token_id", info.TokenID,
		)
		s.markStatus(ctx, evt.ID, event.NotifyFailed, nil)
		return
	}

	if err := sender.Send(ctx, info, evt); err != nil {
		s.logger.WarnContext(ctx, "notify: send failed",
			"channel", info.AlertChannel,
			"event_id", evt.ID,
			"token_id", info.TokenID,
			"error", err,
		)
		s.markStatus(ctx, evt.ID, event.NotifyFailed, nil)
		return
	}

	now := time.Now().UTC()
	s.markStatus(ctx, evt.ID, event.NotifySent, &now)
}

func (s *Service) markStatus(
	ctx context.Context,
	eventID int64,
	status event.NotifyStatus,
	sentAt *time.Time,
) {
	if s.status == nil {
		return
	}
	if err := s.status.UpdateNotifyStatus(
		ctx,
		eventID,
		status,
		sentAt,
	); err != nil {
		s.logger.WarnContext(ctx, "notify: status writeback failed",
			"event_id", eventID,
			"status", status,
			"error", err,
		)
	}
}
