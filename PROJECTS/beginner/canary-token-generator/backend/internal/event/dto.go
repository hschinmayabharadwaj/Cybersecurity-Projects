// ©AngelaMos | 2026
// dto.go

package event

import (
	"encoding/json"
	"time"
)

type GeoView struct {
	Country *string `json:"country"`
	Region  *string `json:"region"`
	City    *string `json:"city"`
	ASN     *int    `json:"asn"`
	ASNOrg  *string `json:"asn_org"`
}

type Response struct {
	ID           int64           `json:"id"`
	TriggeredAt  time.Time       `json:"triggered_at"`
	SourceIP     string          `json:"source_ip"`
	UserAgent    *string         `json:"user_agent"`
	Referer      *string         `json:"referer"`
	Geo          GeoView         `json:"geo"`
	Extra        json.RawMessage `json:"extra"`
	NotifyStatus NotifyStatus    `json:"notify_status"`
	NotifiedAt   *time.Time      `json:"notified_at"`
}

func (e *Event) ToResponse() Response {
	return Response{
		ID:          e.ID,
		TriggeredAt: e.TriggeredAt,
		SourceIP:    e.SourceIP,
		UserAgent:   e.UserAgent,
		Referer:     e.Referer,
		Geo: GeoView{
			Country: e.GeoCountry,
			Region:  e.GeoRegion,
			City:    e.GeoCity,
			ASN:     e.GeoASN,
			ASNOrg:  e.GeoASNOrg,
		},
		Extra:        e.Extra,
		NotifyStatus: e.NotifyStatus,
		NotifiedAt:   e.NotifiedAt,
	}
}
