// ©AngelaMos | 2026
// types.go

package notify

import (
	"context"
	"time"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
)

type Sender interface {
	Channel() string
	Send(
		ctx context.Context,
		info event.NotifyInfo,
		evt *event.Event,
	) error
}

type StatusWriter interface {
	UpdateNotifyStatus(
		ctx context.Context,
		eventID int64,
		status event.NotifyStatus,
		sentAt *time.Time,
	) error
}
