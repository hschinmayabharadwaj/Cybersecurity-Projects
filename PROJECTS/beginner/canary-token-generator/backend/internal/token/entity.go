// ©AngelaMos | 2026
// entity.go

package token

import (
	"encoding/json"
	"time"
)

type Type string

const (
	TypeWebbug       Type = "webbug"
	TypeSlowRedirect Type = "slowredirect"
	TypeDocx         Type = "docx"
	TypePDF          Type = "pdf"
	TypeKubeconfig   Type = "kubeconfig"
	TypeEnvfile      Type = "envfile"
	TypeMySQL        Type = "mysql"
)

func (t Type) Valid() bool {
	switch t {
	case TypeWebbug, TypeSlowRedirect, TypeDocx, TypePDF,
		TypeKubeconfig, TypeEnvfile, TypeMySQL:
		return true
	}
	return false
}

type AlertChannel string

const (
	ChannelTelegram AlertChannel = "telegram"
	ChannelWebhook  AlertChannel = "webhook"
)

func (c AlertChannel) Valid() bool {
	switch c {
	case ChannelTelegram, ChannelWebhook:
		return true
	}
	return false
}

type Token struct {
	ID            string          `db:"id"             json:"id"`
	ManageID      string          `db:"manage_id"      json:"manage_id"`
	Type          Type            `db:"type"           json:"type"`
	Memo          string          `db:"memo"           json:"memo"`
	Filename      *string         `db:"filename"       json:"filename"`
	AlertChannel  AlertChannel    `db:"alert_channel"  json:"alert_channel"`
	TelegramBot   *string         `db:"telegram_bot"   json:"-"`
	TelegramChat  *string         `db:"telegram_chat"  json:"-"`
	WebhookURL    *string         `db:"webhook_url"    json:"-"`
	CreatedAt     time.Time       `db:"created_at"     json:"created_at"`
	CreatedIP     string          `db:"created_ip"     json:"-"`
	CreatedFP     string          `db:"created_fp"     json:"-"`
	Enabled       bool            `db:"enabled"        json:"enabled"`
	TriggerCount  int64           `db:"trigger_count"  json:"trigger_count"`
	LastTriggered *time.Time      `db:"last_triggered" json:"last_triggered"`
	Metadata      json.RawMessage `db:"metadata"       json:"metadata"`
}
