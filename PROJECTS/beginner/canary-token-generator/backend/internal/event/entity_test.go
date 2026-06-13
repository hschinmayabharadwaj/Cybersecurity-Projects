// ©AngelaMos | 2026
// entity_test.go

package event_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/geoip"
)

func TestEvent_AttachGeoIP_PopulatesAllFields(t *testing.T) {
	t.Parallel()
	e := &event.Event{}
	e.AttachGeoIP(geoip.Lookup{
		Country: "US",
		Region:  "California",
		City:    "Mountain View",
		ASN:     15169,
		ASNOrg:  "Google LLC",
	})

	require.NotNil(t, e.GeoCountry)
	require.Equal(t, "US", *e.GeoCountry)
	require.NotNil(t, e.GeoRegion)
	require.Equal(t, "California", *e.GeoRegion)
	require.NotNil(t, e.GeoCity)
	require.Equal(t, "Mountain View", *e.GeoCity)
	require.NotNil(t, e.GeoASN)
	require.Equal(t, 15169, *e.GeoASN)
	require.NotNil(t, e.GeoASNOrg)
	require.Equal(t, "Google LLC", *e.GeoASNOrg)
}

func TestEvent_AttachGeoIP_EmptyLookupLeavesAllNil(t *testing.T) {
	t.Parallel()
	e := &event.Event{}
	e.AttachGeoIP(geoip.Lookup{})

	require.Nil(t, e.GeoCountry)
	require.Nil(t, e.GeoRegion)
	require.Nil(t, e.GeoCity)
	require.Nil(t, e.GeoASN)
	require.Nil(t, e.GeoASNOrg)
}

func TestEvent_AttachGeoIP_PartialFieldsPopulated(t *testing.T) {
	t.Parallel()
	e := &event.Event{}
	e.AttachGeoIP(geoip.Lookup{Country: "JP", City: "Tokyo"})

	require.NotNil(t, e.GeoCountry)
	require.Equal(t, "JP", *e.GeoCountry)
	require.Nil(t, e.GeoRegion)
	require.NotNil(t, e.GeoCity)
	require.Equal(t, "Tokyo", *e.GeoCity)
	require.Nil(t, e.GeoASN)
	require.Nil(t, e.GeoASNOrg)
}

func TestEvent_AttachGeoIP_ZeroASNStaysNil(t *testing.T) {
	t.Parallel()
	e := &event.Event{}
	e.AttachGeoIP(geoip.Lookup{Country: "FR", ASN: 0, ASNOrg: ""})
	require.Nil(t, e.GeoASN,
		"ASN=0 (sentinel for missing) must not produce a pointer")
}

func TestEvent_AttachGeoIP_NegativeASNStaysNil(t *testing.T) {
	t.Parallel()
	e := &event.Event{}
	e.AttachGeoIP(geoip.Lookup{ASN: -1})
	require.Nil(t, e.GeoASN,
		"defensive: negative ASN is invalid and must not produce a pointer")
}

func TestEvent_AttachGeoIP_OverwritesPriorValues(t *testing.T) {
	t.Parallel()
	prior := "OLD"
	priorASN := 99
	e := &event.Event{
		GeoCountry: &prior,
		GeoRegion:  &prior,
		GeoCity:    &prior,
		GeoASNOrg:  &prior,
		GeoASN:     &priorASN,
	}
	e.AttachGeoIP(geoip.Lookup{Country: "DE", City: "Berlin"})

	require.NotNil(t, e.GeoCountry)
	require.Equal(t, "DE", *e.GeoCountry)
	require.Nil(t, e.GeoRegion,
		"AttachGeoIP must overwrite a prior value with nil when "+
			"the new lookup is empty")
	require.NotNil(t, e.GeoCity)
	require.Equal(t, "Berlin", *e.GeoCity)
	require.Nil(t, e.GeoASN)
	require.Nil(t, e.GeoASNOrg)
}

func TestEvent_AttachGeoIP_AddressableASNPointer(t *testing.T) {
	t.Parallel()
	e := &event.Event{}
	e.AttachGeoIP(geoip.Lookup{ASN: 64512})
	require.NotNil(t, e.GeoASN)
	require.Equal(t, 64512, *e.GeoASN)

	*e.GeoASN = 1
	require.Equal(t, 1, *e.GeoASN,
		"ASN pointer must be independently mutable, "+
			"not aliasing the input Lookup")
}
