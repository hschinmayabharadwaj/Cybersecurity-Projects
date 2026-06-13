// ©AngelaMos | 2026
// dto.go

package token

import (
	"encoding/json"
	"time"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
)

type CreateRequest struct {
	Type          Type            `json:"type"                  validate:"required,oneof=webbug slowredirect docx pdf kubeconfig envfile mysql"`
	Memo          string          `json:"memo"                  validate:"max=256"`
	Filename      string          `json:"filename"              validate:"max=128"`
	AlertChannel  AlertChannel    `json:"alert_channel"         validate:"required,oneof=telegram webhook"`
	TelegramBot   string          `json:"telegram_bot"          validate:"required_if=AlertChannel telegram"`
	TelegramChat  string          `json:"telegram_chat"         validate:"required_if=AlertChannel telegram"`
	WebhookURL    string          `json:"webhook_url"           validate:"required_if=AlertChannel webhook,omitempty,url"`
	Metadata      json.RawMessage `json:"metadata"`
	TurnstileResp string          `json:"cf_turnstile_response"`
}

type Response struct {
	ID            string          `json:"id"`
	ManageID      string          `json:"manage_id"`
	Type          Type            `json:"type"`
	Memo          string          `json:"memo"`
	Filename      *string         `json:"filename"`
	AlertChannel  AlertChannel    `json:"alert_channel"`
	CreatedAt     time.Time       `json:"created_at"`
	TriggerCount  int64           `json:"trigger_count"`
	LastTriggered *time.Time      `json:"last_triggered"`
	Enabled       bool            `json:"enabled"`
	TriggerURL    string          `json:"trigger_url"`
	ManageURL     string          `json:"manage_url"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
}

func (t *Token) ToResponse(triggerURL, manageURL string) Response {
	return Response{
		ID:            t.ID,
		ManageID:      t.ManageID,
		Type:          t.Type,
		Memo:          t.Memo,
		Filename:      t.Filename,
		AlertChannel:  t.AlertChannel,
		CreatedAt:     t.CreatedAt,
		TriggerCount:  t.TriggerCount,
		LastTriggered: t.LastTriggered,
		Enabled:       t.Enabled,
		TriggerURL:    triggerURL,
		ManageURL:     manageURL,
		Metadata:      t.Metadata,
	}
}

type ManageTokenView struct {
	ID            string       `json:"id"`
	Type          Type         `json:"type"`
	Memo          string       `json:"memo"`
	Filename      *string      `json:"filename"`
	AlertChannel  AlertChannel `json:"alert_channel"`
	CreatedAt     time.Time    `json:"created_at"`
	TriggerCount  int64        `json:"trigger_count"`
	LastTriggered *time.Time   `json:"last_triggered"`
	Enabled       bool         `json:"enabled"`
	TriggerURL    string       `json:"trigger_url"`
}

type ManagePage struct {
	NextCursor string `json:"next_cursor"`
	HasMore    bool   `json:"has_more"`
}

type ManageResponse struct {
	Token                ManageTokenView  `json:"token"`
	Events               []event.Response `json:"events"`
	EventsTotal          int64            `json:"events_total"`
	EventsSilencedActive int64            `json:"events_silenced_active"`
	Page                 ManagePage       `json:"page"`
}

func (t *Token) ToManageView(triggerURL string) ManageTokenView {
	return ManageTokenView{
		ID:            t.ID,
		Type:          t.Type,
		Memo:          t.Memo,
		Filename:      t.Filename,
		AlertChannel:  t.AlertChannel,
		CreatedAt:     t.CreatedAt,
		TriggerCount:  t.TriggerCount,
		LastTriggered: t.LastTriggered,
		Enabled:       t.Enabled,
		TriggerURL:    triggerURL,
	}
}
