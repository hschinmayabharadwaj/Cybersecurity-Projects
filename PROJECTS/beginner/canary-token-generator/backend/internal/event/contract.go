// ©AngelaMos | 2026
// contract.go

package event

import (
	"context"
	"time"
)

type NotifyInfo struct {
	TokenID      string
	ManageID     string
	Type         string
	Memo         string
	AlertChannel string
	TelegramBot  string
	TelegramChat string
	WebhookURL   string
}

type Notifier interface {
	Notify(info NotifyInfo, evt *Event)
}

type TokenIncrementer interface {
	IncrementTriggerCount(ctx context.Context, id string) error
}

type Store interface {
	Insert(ctx context.Context, e *Event) error
	UpdateNotifyStatus(
		ctx context.Context,
		eventID int64,
		status NotifyStatus,
		sentAt *time.Time,
	) error
	PruneToLimit(ctx context.Context, perTokenLimit int) (int64, error)
}
