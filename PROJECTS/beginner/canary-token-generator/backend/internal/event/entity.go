// ©AngelaMos | 2026
// entity.go

package event

import (
	"encoding/json"
	"time"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/geoip"
)

type NotifyStatus string

const (
	NotifyPending NotifyStatus = "pending"
	NotifySent    NotifyStatus = "sent"
	NotifyFailed  NotifyStatus = "failed"
	NotifyDeduped NotifyStatus = "deduped"
)

func (s NotifyStatus) Valid() bool {
	switch s {
	case NotifyPending, NotifySent, NotifyFailed, NotifyDeduped:
		return true
	}
	return false
}

type Event struct {
	ID           int64           `db:"id"            json:"id"`
	TokenID      string          `db:"token_id"      json:"token_id"`
	TriggeredAt  time.Time       `db:"triggered_at"  json:"triggered_at"`
	SourceIP     string          `db:"source_ip"     json:"source_ip"`
	UserAgent    *string         `db:"user_agent"    json:"user_agent"`
	Referer      *string         `db:"referer"       json:"referer"`
	GeoCountry   *string         `db:"geo_country"   json:"geo_country"`
	GeoRegion    *string         `db:"geo_region"    json:"geo_region"`
	GeoCity      *string         `db:"geo_city"      json:"geo_city"`
	GeoASN       *int            `db:"geo_asn"       json:"geo_asn"`
	GeoASNOrg    *string         `db:"geo_asn_org"   json:"geo_asn_org"`
	Extra        json.RawMessage `db:"extra"         json:"extra"`
	NotifyStatus NotifyStatus    `db:"notify_status" json:"notify_status"`
	NotifiedAt   *time.Time      `db:"notified_at"   json:"notified_at"`
}

func (e *Event) AttachGeoIP(l geoip.Lookup) {
	e.GeoCountry = nonEmptyPtr(l.Country)
	e.GeoRegion = nonEmptyPtr(l.Region)
	e.GeoCity = nonEmptyPtr(l.City)
	e.GeoASNOrg = nonEmptyPtr(l.ASNOrg)
	if l.ASN > 0 {
		asn := l.ASN
		e.GeoASN = &asn
		return
	}
	e.GeoASN = nil
}

func nonEmptyPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
