// ©AngelaMos | 2026
// generator_test.go

package slowredirect_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/slowredirect"
)

const (
	cspOverride         = "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'"
	cacheControlNoStore = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaNoCache       = "no-cache"
	contentTypeHTML     = "text/html; charset=utf-8"
)

func newSlowRedirectToken(t testing.TB, id, destination string) *token.Token {
	t.Helper()
	metadata := json.RawMessage(`{}`)
	if destination != "" {
		raw, err := json.Marshal(map[string]string{
			"destination_url": destination,
		})
		require.NoError(t, err)
		metadata = raw
	}
	return &token.Token{
		ID:           id,
		ManageID:     "manage-" + id,
		Type:         token.TypeSlowRedirect,
		Memo:         "unit test slowredirect",
		AlertChannel: token.ChannelWebhook,
		Enabled:      true,
		Metadata:     metadata,
	}
}

func TestGenerator_TypeIsSlowRedirect(t *testing.T) {
	g := slowredirect.New()
	require.Equal(t, token.TypeSlowRedirect, g.Type())
}

func TestGenerate_PersistsDestinationOnToken(t *testing.T) {
	cases := []struct {
		name        string
		baseURL     string
		id          string
		destination string
		wantURL     string
	}{
		{
			name:        "plain destination",
			baseURL:     "https://canary.example.com",
			id:          "abc123",
			destination: "https://news.example.com/article/42",
			wantURL:     "https://canary.example.com/c/abc123",
		},
		{
			name:        "trailing slash trimmed on base URL",
			baseURL:     "https://canary.example.com/",
			id:          "xyz999",
			destination: "https://news.example.com",
			wantURL:     "https://canary.example.com/c/xyz999",
		},
		{
			name:        "subpath base URL preserved",
			baseURL:     "https://example.com/canary",
			id:          "p7",
			destination: "https://other.example.com",
			wantURL:     "https://example.com/canary/c/p7",
		},
	}

	g := slowredirect.New()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tok := newSlowRedirectToken(t, tc.id, tc.destination)
			art, err := g.Generate(
				context.Background(),
				tok,
				tc.baseURL,
			)
			require.NoError(t, err)
			require.Equal(t, generators.KindURL, art.Kind)
			require.Equal(t, tc.wantURL, art.URL)
			require.Equal(
				t,
				tc.destination,
				art.DestinationURL,
				"artifact must surface destination_url that was persisted on the token metadata",
			)
		})
	}
}

func TestGenerate_RejectsMissingDestination(t *testing.T) {
	cases := []struct {
		name     string
		metadata json.RawMessage
		wantErr  error
	}{
		{
			name:     "empty metadata",
			metadata: json.RawMessage(``),
			wantErr:  slowredirect.ErrMissingDestination,
		},
		{
			name:     "empty object",
			metadata: json.RawMessage(`{}`),
			wantErr:  slowredirect.ErrMissingDestination,
		},
		{
			name:     "empty destination string",
			metadata: json.RawMessage(`{"destination_url":""}`),
			wantErr:  slowredirect.ErrMissingDestination,
		},
		{
			name:     "whitespace destination",
			metadata: json.RawMessage(`{"destination_url":"   "}`),
			wantErr:  slowredirect.ErrMissingDestination,
		},
		{
			name:     "wrong key",
			metadata: json.RawMessage(`{"redirect":"https://example.com"}`),
			wantErr:  slowredirect.ErrMissingDestination,
		},
	}

	g := slowredirect.New()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tok := &token.Token{
				ID:       "missingdest",
				Type:     token.TypeSlowRedirect,
				Metadata: tc.metadata,
			}
			_, err := g.Generate(
				context.Background(),
				tok,
				"https://canary.example.com",
			)
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestGenerate_RejectsDangerousDestinationSchemes(t *testing.T) {
	cases := []struct {
		name        string
		destination string
	}{
		{name: "javascript: scheme", destination: "javascript:alert(1)"},
		{
			name:        "javascript: scheme with mixed case",
			destination: "JavaScript:alert(1)",
		},
		{
			name:        "data: URI",
			destination: "data:text/html;base64,PHNjcmlwdD4=",
		},
		{name: "file: scheme", destination: "file:///etc/passwd"},
		{name: "vbscript: scheme", destination: "vbscript:msgbox(1)"},
		{name: "no scheme", destination: "example.com/path"},
		{name: "relative path", destination: "/path"},
		{name: "protocol-relative", destination: "//example.com"},
	}

	g := slowredirect.New()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tok := newSlowRedirectToken(t, "schemecheck1", tc.destination)
			_, err := g.Generate(
				context.Background(),
				tok,
				"https://canary.example.com",
			)
			require.ErrorIs(
				t,
				err,
				slowredirect.ErrInvalidDestinationScheme,
				"destination scheme %q must be rejected to keep the noscript meta-refresh from following dangerous URIs when JS is disabled",
				tc.destination,
			)
		})
	}
}

func TestGenerate_AcceptsHTTPAndHTTPSSchemes(t *testing.T) {
	g := slowredirect.New()
	cases := []string{
		"http://news.example.com",
		"https://news.example.com",
		"HTTP://news.example.com",
		"HtTpS://news.example.com",
	}
	for _, dest := range cases {
		dest := dest
		t.Run(dest, func(t *testing.T) {
			tok := newSlowRedirectToken(t, "schemeok0001", dest)
			art, err := g.Generate(
				context.Background(),
				tok,
				"https://canary.example.com",
			)
			require.NoError(t, err)
			require.Equal(t, dest, art.DestinationURL)
		})
	}
}

func TestTrigger_RendersHTMLWithEscapedDestination(t *testing.T) {
	g := slowredirect.New()

	t.Run("plain destination renders into JS and noscript", func(t *testing.T) {
		dest := "https://news.example.com/article"
		tok := newSlowRedirectToken(t, "plainok01", dest)
		r := httptest.NewRequest(http.MethodGet, "/c/plainok01", nil)
		r.Header.Set("CF-Connecting-IP", "203.0.113.7")

		evt, resp, err := g.Trigger(context.Background(), tok, r)
		require.NoError(t, err)
		require.NotNil(t, evt)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, contentTypeHTML, resp.ContentType)

		body := string(resp.Body)
		require.Contains(
			t,
			body,
			`url=https://news.example.com/article`,
			"noscript meta refresh must point at the destination",
		)
		require.Contains(
			t,
			body,
			"https://news.example.com/article",
			"JS body must include the destination for window.location.replace",
		)
		require.Contains(
			t,
			body,
			"/c/plainok01/fingerprint",
			"JS body must reference the per-token fingerprint endpoint",
		)
	})

	t.Run("XSS attempt in destination is neutralized", func(t *testing.T) {
		hostile := `https://x.example.com/" /></noscript><script>alert(1)</script>`
		tok := newSlowRedirectToken(t, "xssa001", hostile)
		r := httptest.NewRequest(http.MethodGet, "/c/xssa001", nil)

		_, resp, err := g.Trigger(context.Background(), tok, r)
		require.NoError(t, err)
		body := string(resp.Body)

		require.NotContains(
			t,
			body,
			"<script>alert(1)</script>",
			"raw script injection must not appear unescaped in any context",
		)
		require.NotContains(
			t,
			body,
			`/></noscript><script>`,
			"attribute-context injection must be HTML-escaped",
		)
		require.Equal(
			t,
			1,
			strings.Count(body, "<script>"),
			"only the trusted inline script tag may appear",
		)
		require.Equal(
			t,
			1,
			strings.Count(body, "</script>"),
			"only the trusted inline script closing tag may appear",
		)
	})

	t.Run("script-closing injection is neutralized", func(t *testing.T) {
		hostile := `https://x.example.com/</script><img src=x onerror=alert(1)>`
		tok := newSlowRedirectToken(t, "xssb001", hostile)
		r := httptest.NewRequest(http.MethodGet, "/c/xssb001", nil)

		_, resp, err := g.Trigger(context.Background(), tok, r)
		require.NoError(t, err)
		body := string(resp.Body)

		require.NotContains(
			t,
			body,
			"</script><img",
			"closing-script-tag escape must be applied inside JS contexts",
		)
	})
}

func TestTrigger_DestinationRoundtripsThroughJSStringDecode(t *testing.T) {
	g := slowredirect.New()
	const dest = "https://news.example.com/article?utm_source=newsletter&utm_medium=email&id=42"

	tok := newSlowRedirectToken(t, "rndtrip001", dest)
	r := httptest.NewRequest(http.MethodGet, "/c/rndtrip001", nil)

	_, resp, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)
	body := string(resp.Body)

	require.NotContains(
		t,
		body,
		`\\u003D`,
		"double-backslash unicode escape means {{...|js}} double-ran the JS escaper; browsers would see literal \\u003D text instead of '='",
	)
	require.NotContains(
		t,
		body,
		`\\u0026`,
		"double-backslash unicode escape would corrupt '&' in real query strings",
	)
	require.Contains(
		t,
		body,
		`=`,
		"html/template auto-escape should emit single-backslash \\u003D so JS parser decodes to '='",
	)
	require.Contains(
		t,
		body,
		`&`,
		"html/template auto-escape should emit single-backslash \\u0026 for '&'",
	)
}

func TestTrigger_SetsCSPOverride(t *testing.T) {
	g := slowredirect.New()
	tok := newSlowRedirectToken(t, "cspok001", "https://news.example.com")
	r := httptest.NewRequest(http.MethodGet, "/c/cspok001", nil)

	_, resp, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)
	require.NotNil(t, resp)

	csp, ok := resp.ExtraHeaders["Content-Security-Policy"]
	require.True(
		t,
		ok,
		"Content-Security-Policy must be set on trigger response",
	)
	require.Equal(t, cspOverride, csp)
	require.Equal(
		t,
		cacheControlNoStore,
		resp.ExtraHeaders["Cache-Control"],
		"cache-control must prevent intermediary caching",
	)
	require.Equal(
		t,
		pragmaNoCache,
		resp.ExtraHeaders["Pragma"],
		"pragma must be set for HTTP/1.0 caches",
	)
}

func TestTrigger_RecordsEventWithRequestMetadata(t *testing.T) {
	g := slowredirect.New()
	tok := newSlowRedirectToken(t, "evtok001", "https://news.example.com")
	r := httptest.NewRequest(http.MethodGet, "/c/evtok001", nil)
	r.Header.Set("CF-Connecting-IP", "203.0.113.55")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Referer", "https://mail.example.com/inbox")

	evt, _, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)
	require.NotNil(t, evt)
	require.Equal(t, "evtok001", evt.TokenID)
	require.Equal(t, "203.0.113.55", evt.SourceIP)
	require.NotNil(t, evt.UserAgent)
	require.Equal(t, "Mozilla/5.0", *evt.UserAgent)
	require.NotNil(t, evt.Referer)
	require.Equal(t, "https://mail.example.com/inbox", *evt.Referer)
}

func TestTrigger_TokenNotFound_ReturnsNilEvent(t *testing.T) {
	g := slowredirect.New()
	r := httptest.NewRequest(http.MethodGet, "/c/does-not-exist", nil)
	r.Header.Set("CF-Connecting-IP", "203.0.113.100")

	evt, resp, err := g.Trigger(context.Background(), nil, r)
	require.NoError(
		t,
		err,
		"nil-token path must not error (spec §8.5 defense-in-depth)",
	)
	require.NotNil(t, resp)
	require.Nil(
		t,
		evt,
		"nil-token path returns nil event so the handler cannot accidentally insert an event row with empty TokenID",
	)
	require.Equal(
		t,
		http.StatusOK,
		resp.StatusCode,
		"nil-token path must return 200 — spec §8.5 forbids 404 on /c/* to prevent token-existence enumeration",
	)
	require.Equal(
		t,
		contentTypeHTML,
		resp.ContentType,
		"nil-token response must be indistinguishable in shape from a real slowredirect response",
	)
	require.NotEmpty(t, resp.Body)
}

func TestTrigger_TokenNotFound_HasSameResponseShapeAsValidToken(t *testing.T) {
	g := slowredirect.New()
	r := httptest.NewRequest(http.MethodGet, "/c/anything", nil)

	tok := newSlowRedirectToken(t, "shapecmp001", "https://news.example.com")
	_, validResp, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)

	_, decoyResp, err := g.Trigger(context.Background(), nil, r)
	require.NoError(t, err)

	require.Equal(t, validResp.StatusCode, decoyResp.StatusCode)
	require.Equal(t, validResp.ContentType, decoyResp.ContentType)
	require.Equal(
		t,
		validResp.ExtraHeaders["Content-Security-Policy"],
		decoyResp.ExtraHeaders["Content-Security-Policy"],
	)
	require.Contains(
		t,
		string(decoyResp.Body),
		"<noscript>",
		"decoy body must keep the noscript+script structure so a scanner cannot fingerprint token presence by body shape",
	)
	require.Contains(t, string(decoyResp.Body), "<script>")
}

func TestTrigger_BodyIsIndependentCopyPerCall(t *testing.T) {
	g := slowredirect.New()
	tok := newSlowRedirectToken(t, "indep001", "https://news.example.com")
	r := httptest.NewRequest(http.MethodGet, "/c/indep001", nil)

	_, resp1, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)
	_, resp2, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)

	resp1.Body[0] = 0x00
	require.NotEqual(
		t,
		byte(0x00),
		resp2.Body[0],
		"each Trigger call must produce an independent body slice — shared template buffer would corrupt concurrent responses",
	)
}
