// ©AngelaMos | 2026
// contract.go

package token

import (
	"context"
	"net/http"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
)

type ArtifactKind string

const (
	KindURL              ArtifactKind = "url"
	KindFile             ArtifactKind = "file"
	KindText             ArtifactKind = "text"
	KindConnectionString ArtifactKind = "connection_string"
)

type Artifact struct {
	Kind             ArtifactKind
	URL              string
	Filename         string
	Content          []byte
	ContentType      string
	ConnectionString string
	DestinationURL   string
}

type TriggerResponse struct {
	StatusCode   int
	ContentType  string
	Body         []byte
	RedirectURL  string
	ExtraHeaders map[string]string
}

type Generator interface {
	Type() Type
	Generate(
		ctx context.Context,
		t *Token,
		baseURL string,
	) (Artifact, error)
	Trigger(
		ctx context.Context,
		t *Token,
		r *http.Request,
	) (*event.Event, *TriggerResponse, error)
}

func (t *Token) NotifyInfo() event.NotifyInfo {
	return event.NotifyInfo{
		TokenID:      t.ID,
		ManageID:     t.ManageID,
		Type:         string(t.Type),
		Memo:         t.Memo,
		AlertChannel: string(t.AlertChannel),
		TelegramBot:  derefString(t.TelegramBot),
		TelegramChat: derefString(t.TelegramChat),
		WebhookURL:   derefString(t.WebhookURL),
	}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
