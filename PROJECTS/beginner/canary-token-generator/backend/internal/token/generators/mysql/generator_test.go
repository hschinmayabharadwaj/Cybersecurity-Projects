// ©AngelaMos | 2026
// generator_test.go

package mysql_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/mysql"
)

func newMySQLToken(id string) *token.Token {
	return &token.Token{
		ID:           id,
		ManageID:     "manage-" + id,
		Type:         token.TypeMySQL,
		Memo:         "unit test mysql",
		AlertChannel: token.ChannelWebhook,
		Enabled:      true,
	}
}

func TestGenerator_TypeIsMySQL(t *testing.T) {
	require.Equal(t, token.TypeMySQL, mysql.New().Type())
}

func TestGenerate_ArtifactKindIsConnectionString(t *testing.T) {
	g := mysql.New()
	art, err := g.Generate(context.Background(), newMySQLToken("abc"), "")
	require.NoError(t, err)
	require.Equal(t, generators.KindConnectionString, art.Kind)
}

func TestGenerate_ConnectionStringDefaultLocalhost(t *testing.T) {
	g := mysql.New()
	art, err := g.Generate(context.Background(), newMySQLToken("abc"), "")
	require.NoError(t, err)
	require.Equal(
		t,
		"mysql://canary_abc@localhost:3306/internal_db",
		art.ConnectionString,
	)
}

func TestGenerate_ConnectionStringCustomAddress(t *testing.T) {
	g := mysql.NewWithAddress("canary.example.com", 13306)
	art, err := g.Generate(context.Background(), newMySQLToken("xyz"), "")
	require.NoError(t, err)
	require.Equal(
		t,
		"mysql://canary_xyz@canary.example.com:13306/internal_db",
		art.ConnectionString,
	)
}

func TestGenerate_UsernamePrefixIsCanary_(t *testing.T) {
	g := mysql.New()
	art, err := g.Generate(context.Background(), newMySQLToken("probeid"), "")
	require.NoError(t, err)
	require.Contains(
		t,
		art.ConnectionString,
		"canary_probeid@",
		"username must be canary_+token.ID for TCP-side lookup parity",
	)
}

func TestGenerate_PersistsMySQLUsernameInMetadata(t *testing.T) {
	g := mysql.New()
	tok := newMySQLToken("abc")
	require.Empty(t, tok.Metadata, "fresh token has no metadata yet")

	_, err := g.Generate(context.Background(), tok, "")
	require.NoError(t, err)

	require.NotEmpty(
		t,
		tok.Metadata,
		"Generate must persist mysql_username into token metadata",
	)

	var m map[string]any
	require.NoError(t, json.Unmarshal(tok.Metadata, &m))
	require.Equal(t, "canary_abc", m["mysql_username"])
}

func TestGenerate_PreservesExistingMetadataFields(t *testing.T) {
	g := mysql.New()
	tok := newMySQLToken("abc")
	tok.Metadata = json.RawMessage(`{"existing_field":"keep_me","other":42}`)

	_, err := g.Generate(context.Background(), tok, "")
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(tok.Metadata, &m))
	require.Equal(t, "keep_me", m["existing_field"])
	other, ok := m["other"].(float64)
	require.True(t, ok)
	require.Equal(t, 42, int(other))
	require.Equal(t, "canary_abc", m["mysql_username"])
}

func TestGenerate_MalformedMetadataIsReplaced(t *testing.T) {
	g := mysql.New()
	tok := newMySQLToken("abc")
	tok.Metadata = json.RawMessage(`{not valid json`)

	_, err := g.Generate(context.Background(), tok, "")
	require.NoError(
		t,
		err,
		"malformed metadata must not block generation — replace with a fresh map",
	)

	var m map[string]any
	require.NoError(t, json.Unmarshal(tok.Metadata, &m))
	require.Equal(t, "canary_abc", m["mysql_username"])
}

func TestGenerate_OverwritesPriorMySQLUsername(t *testing.T) {
	g := mysql.New()
	tok := newMySQLToken("abc")
	tok.Metadata = json.RawMessage(`{"mysql_username":"stale_value"}`)

	_, err := g.Generate(context.Background(), tok, "")
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(tok.Metadata, &m))
	require.Equal(
		t,
		"canary_abc",
		m["mysql_username"],
		"regeneration must overwrite stale mysql_username with the current token's",
	)
}

func TestGenerate_BaseURLIgnored(t *testing.T) {
	g := mysql.New()

	art1, err := g.Generate(
		context.Background(),
		newMySQLToken("abc"),
		"https://canary.example.com",
	)
	require.NoError(t, err)
	art2, err := g.Generate(
		context.Background(),
		newMySQLToken("abc"),
		"https://different.example.com/sub",
	)
	require.NoError(t, err)
	require.Equal(
		t,
		art1.ConnectionString,
		art2.ConnectionString,
		"baseURL is irrelevant to mysql connection strings",
	)
}

func TestTrigger_ReturnsHTTPNotSupportedError(t *testing.T) {
	g := mysql.New()
	r := httptest.NewRequest(http.MethodGet, "/c/abc", nil)

	evt, resp, err := g.Trigger(
		context.Background(),
		newMySQLToken("abc"),
		r,
	)
	require.Error(t, err)
	require.ErrorIs(t, err, mysql.ErrHTTPTriggerNotSupported)
	require.Nil(t, evt, "no event when HTTP-triggered (mysql uses TCP)")
	require.Nil(t, resp, "no response when HTTP-triggered (mysql uses TCP)")
}

func TestTrigger_NilTokenAlsoReturnsHTTPNotSupportedError(t *testing.T) {
	g := mysql.New()
	r := httptest.NewRequest(http.MethodGet, "/c/abc", nil)

	_, _, err := g.Trigger(context.Background(), nil, r)
	require.ErrorIs(t, err, mysql.ErrHTTPTriggerNotSupported)
}
