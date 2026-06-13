// ©AngelaMos | 2026
// generator_test.go

package envfile_test

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
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/envfile"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/pixel"
)

const (
	testBaseURL              = "https://canary.example.com"
	envfileContentTypeMIME   = "text/plain; charset=utf-8"
	defaultFilenameValue     = ".env"
	cacheControlNoStoreValue = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaNoCacheValue       = "no-cache"
	gifByteLength            = 43
)

func newEnvfileToken(id string) *token.Token {
	return &token.Token{
		ID:           id,
		ManageID:     "manage-" + id,
		Type:         token.TypeEnvfile,
		Memo:         "unit test envfile",
		AlertChannel: token.ChannelWebhook,
		Enabled:      true,
	}
}

func newEnvfileTokenWithFilename(id, filename string) *token.Token {
	tok := newEnvfileToken(id)
	tok.Filename = &filename
	return tok
}

func newEnvfileTokenWithIncludeKeys(keys []string) *token.Token {
	tok := newEnvfileToken("abc")
	raw, err := json.Marshal(map[string]any{"include_keys": keys})
	if err != nil {
		panic(err)
	}
	tok.Metadata = raw
	return tok
}

func newEnvfileTokenWithRawMetadata(metadata string) *token.Token {
	tok := newEnvfileToken("abc")
	tok.Metadata = json.RawMessage(metadata)
	return tok
}

func envLines(content []byte) []string {
	return strings.Split(string(content), "\n")
}

func TestGenerator_TypeIsEnvfile(t *testing.T) {
	g := envfile.New()
	require.Equal(t, token.TypeEnvfile, g.Type())
}

func TestGenerate_ArtifactKindIsText(t *testing.T) {
	g := envfile.New()
	art, err := g.Generate(
		context.Background(),
		newEnvfileToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)
	require.Equal(t, generators.KindText, art.Kind)
}

func TestGenerate_ContentTypeIsTextPlain(t *testing.T) {
	g := envfile.New()
	art, err := g.Generate(
		context.Background(),
		newEnvfileToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)
	require.Equal(t, envfileContentTypeMIME, art.ContentType)
}

func TestGenerate_Filename(t *testing.T) {
	g := envfile.New()

	t.Run("nil Filename defaults to .env", func(t *testing.T) {
		art, err := g.Generate(
			context.Background(),
			newEnvfileToken("abc"),
			testBaseURL,
		)
		require.NoError(t, err)
		require.Equal(t, defaultFilenameValue, art.Filename)
	})

	t.Run("empty Filename pointer defaults to .env", func(t *testing.T) {
		art, err := g.Generate(
			context.Background(),
			newEnvfileTokenWithFilename("abc", ""),
			testBaseURL,
		)
		require.NoError(t, err)
		require.Equal(t, defaultFilenameValue, art.Filename)
	})

	t.Run("whitespace Filename defaults to .env", func(t *testing.T) {
		art, err := g.Generate(
			context.Background(),
			newEnvfileTokenWithFilename("abc", "   "),
			testBaseURL,
		)
		require.NoError(t, err)
		require.Equal(t, defaultFilenameValue, art.Filename)
	})

	t.Run("set Filename is preserved (trimmed)", func(t *testing.T) {
		art, err := g.Generate(
			context.Background(),
			newEnvfileTokenWithFilename("abc", "  .env.production  "),
			testBaseURL,
		)
		require.NoError(t, err)
		require.Equal(t, ".env.production", art.Filename)
	})
}

func TestGenerate_ContainsHeader(t *testing.T) {
	g := envfile.New()
	art, err := g.Generate(
		context.Background(),
		newEnvfileToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)
	body := string(art.Content)
	require.Contains(t, body, "# Production environment")
	require.Contains(t, body, "NODE_ENV=production")
	require.Contains(t, body, "PORT=8080")
}

func TestGenerate_EmbedsCanaryURL(t *testing.T) {
	g := envfile.New()
	art, err := g.Generate(
		context.Background(),
		newEnvfileToken("token42"),
		testBaseURL,
	)
	require.NoError(t, err)
	body := string(art.Content)
	require.Contains(
		t,
		body,
		"INTERNAL_METRICS_ENDPOINT=https://canary.example.com/c/token42",
		"envfile must contain the canary URL as the INTERNAL_METRICS_ENDPOINT line",
	)
}

func TestGenerate_EmbedsCanaryToken(t *testing.T) {
	g := envfile.New()
	art, err := g.Generate(
		context.Background(),
		newEnvfileToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)
	body := string(art.Content)
	require.Regexp(
		t,
		`INTERNAL_METRICS_TOKEN=tok_live_[A-Za-z0-9]{32}`,
		body,
		"INTERNAL_METRICS_TOKEN must follow the tok_live_ + 32-alnum format",
	)
}

func TestGenerate_TriggerURLTrailingSlashTrim(t *testing.T) {
	g := envfile.New()

	artA, err := g.Generate(
		context.Background(),
		newEnvfileToken("tk1"),
		"https://canary.example.com",
	)
	require.NoError(t, err)
	artB, err := g.Generate(
		context.Background(),
		newEnvfileToken("tk1"),
		"https://canary.example.com/",
	)
	require.NoError(t, err)

	require.Contains(
		t,
		string(artA.Content),
		"INTERNAL_METRICS_ENDPOINT=https://canary.example.com/c/tk1",
	)
	require.Contains(
		t,
		string(artB.Content),
		"INTERNAL_METRICS_ENDPOINT=https://canary.example.com/c/tk1",
	)
}

func TestGenerate_DefaultIncludeKeysAreAWSAndDB(t *testing.T) {
	g := envfile.New()
	art, err := g.Generate(
		context.Background(),
		newEnvfileToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)
	body := string(art.Content)
	require.Contains(
		t,
		body,
		"AWS_ACCESS_KEY_ID=",
		"default include_keys should include aws",
	)
	require.Contains(
		t,
		body,
		"DATABASE_URL=postgres://",
		"default include_keys should include db",
	)
	require.NotContains(
		t,
		body,
		"STRIPE_SECRET_KEY=",
		"default include_keys must NOT include stripe",
	)
	require.NotContains(
		t,
		body,
		"GITHUB_TOKEN=",
		"default include_keys must NOT include github",
	)
}

func TestGenerate_IncludeKeysFromMetadata(t *testing.T) {
	g := envfile.New()
	tok := newEnvfileTokenWithIncludeKeys([]string{"stripe", "github"})

	art, err := g.Generate(context.Background(), tok, testBaseURL)
	require.NoError(t, err)
	body := string(art.Content)
	require.Contains(t, body, "STRIPE_SECRET_KEY=")
	require.Contains(t, body, "GITHUB_TOKEN=")
	require.NotContains(t, body, "AWS_ACCESS_KEY_ID=")
	require.NotContains(t, body, "DATABASE_URL=postgres://")
}

func TestGenerate_UnknownKeyInMetadataSkipped(t *testing.T) {
	g := envfile.New()
	tok := newEnvfileTokenWithIncludeKeys(
		[]string{"aws", "nonexistent", "stripe"},
	)

	art, err := g.Generate(context.Background(), tok, testBaseURL)
	require.NoError(t, err)
	body := string(art.Content)
	require.Contains(t, body, "AWS_ACCESS_KEY_ID=")
	require.Contains(t, body, "STRIPE_SECRET_KEY=")
	require.NotContains(t, body, "nonexistent")
}

func TestGenerate_MalformedMetadataFallsBackToDefaults(t *testing.T) {
	g := envfile.New()

	cases := []struct {
		name     string
		metadata string
	}{
		{"empty raw", ""},
		{"invalid json", "{not valid"},
		{"include_keys is not array", `{"include_keys": "aws"}`},
		{"include_keys is null", `{"include_keys": null}`},
		{"include_keys is empty array", `{"include_keys": []}`},
		{"missing include_keys field", `{"other_field": "value"}`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tok := newEnvfileTokenWithRawMetadata(tc.metadata)
			art, err := g.Generate(context.Background(), tok, testBaseURL)
			require.NoError(t, err)
			body := string(art.Content)
			require.Contains(
				t,
				body,
				"AWS_ACCESS_KEY_ID=",
				"malformed metadata must fall back to aws default",
			)
			require.Contains(
				t,
				body,
				"DATABASE_URL=postgres://",
				"malformed metadata must fall back to db default",
			)
		})
	}
}

func TestGenerate_IncludeKeysFiltersEmptyStrings(t *testing.T) {
	g := envfile.New()
	tok := newEnvfileTokenWithIncludeKeys(
		[]string{"", "  ", "aws"},
	)
	art, err := g.Generate(context.Background(), tok, testBaseURL)
	require.NoError(t, err)
	require.Contains(t, string(art.Content), "AWS_ACCESS_KEY_ID=")
}

func TestGenerate_IncludeKeysAllWhitespaceFallsBackToDefaults(t *testing.T) {
	g := envfile.New()
	tok := newEnvfileTokenWithIncludeKeys([]string{"", "  "})
	art, err := g.Generate(context.Background(), tok, testBaseURL)
	require.NoError(t, err)
	body := string(art.Content)
	require.Contains(t, body, "AWS_ACCESS_KEY_ID=")
	require.Contains(t, body, "DATABASE_URL=postgres://")
}

func TestGenerate_SectionShuffleProducesVariableOrder(t *testing.T) {
	g := envfile.New()
	tok := newEnvfileTokenWithIncludeKeys(
		[]string{"aws", "stripe", "github", "db"},
	)

	canaryPositions := make(map[int]struct{})
	for range 30 {
		art, err := g.Generate(context.Background(), tok, testBaseURL)
		require.NoError(t, err)
		lines := envLines(art.Content)
		for i, line := range lines {
			if strings.HasPrefix(line, "INTERNAL_METRICS_ENDPOINT=") {
				canaryPositions[i] = struct{}{}
				break
			}
		}
	}
	require.Greater(
		t,
		len(canaryPositions),
		1,
		"shuffle must place the canary section at varying positions across 30 invocations",
	)
}

func TestGenerate_DistinctInvocationsProduceDistinctOutputs(t *testing.T) {
	g := envfile.New()
	seen := make(map[string]struct{})
	for range 10 {
		art, err := g.Generate(
			context.Background(),
			newEnvfileToken("abc"),
			testBaseURL,
		)
		require.NoError(t, err)
		seen[string(art.Content)] = struct{}{}
	}
	require.Greater(
		t,
		len(seen),
		8,
		"random bait + random canary token + shuffle should produce near-unique outputs",
	)
}

func TestGenerate_TokenIDDoesNotLeakOutsideCanaryLine(t *testing.T) {
	g := envfile.New()
	art, err := g.Generate(
		context.Background(),
		newEnvfileToken("uniqueprobe"),
		testBaseURL,
	)
	require.NoError(t, err)
	body := string(art.Content)
	require.Equal(
		t,
		1,
		strings.Count(body, "uniqueprobe"),
		"token id must appear exactly once (in the canary URL), never in bait lines",
	)
}

func TestTrigger_ReturnsGIFLikeWebbug(t *testing.T) {
	g := envfile.New()
	tok := newEnvfileToken("abc")
	r := httptest.NewRequest(http.MethodGet, "/c/abc", nil)

	_, resp, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, pixel.ContentType, resp.ContentType)
	require.Len(t, resp.Body, gifByteLength)
	require.Equal(t, pixel.Clone(), resp.Body)
	require.Equal(
		t,
		cacheControlNoStoreValue,
		resp.ExtraHeaders["Cache-Control"],
	)
	require.Equal(t, pragmaNoCacheValue, resp.ExtraHeaders["Pragma"])
}

func TestTrigger_RecordsEventWithRequestMetadata(t *testing.T) {
	g := envfile.New()
	tok := newEnvfileToken("token1")

	t.Run(
		"captures token id, source ip, user agent, referer",
		func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/c/token1", nil)
			r.Header.Set("CF-Connecting-IP", "203.0.113.50")
			r.Header.Set("User-Agent", "curl/8.0.0")
			r.Header.Set("Referer", "https://victim.example.com/")

			evt, _, err := g.Trigger(context.Background(), tok, r)
			require.NoError(t, err)
			require.NotNil(t, evt)
			require.Equal(t, "token1", evt.TokenID)
			require.Equal(t, "203.0.113.50", evt.SourceIP)
			require.NotNil(t, evt.UserAgent)
			require.Equal(t, "curl/8.0.0", *evt.UserAgent)
			require.NotNil(t, evt.Referer)
			require.Equal(t, "https://victim.example.com/", *evt.Referer)
		},
	)

	t.Run("source ip precedence", func(t *testing.T) {
		cases := []struct {
			name    string
			headers map[string]string
			remote  string
			wantIP  string
		}{
			{
				name: "CF wins over XFF and XRI",
				headers: map[string]string{
					"CF-Connecting-IP": "203.0.113.10",
					"X-Forwarded-For":  "198.51.100.1, 198.51.100.2",
					"X-Real-IP":        "192.0.2.99",
				},
				remote: "127.0.0.1:9999",
				wantIP: "203.0.113.10",
			},
			{
				name: "XFF leftmost wins over XRI when no CF",
				headers: map[string]string{
					"X-Forwarded-For": "198.51.100.1, 198.51.100.7",
					"X-Real-IP":       "192.0.2.99",
				},
				remote: "127.0.0.1:9999",
				wantIP: "198.51.100.1",
			},
			{
				name: "XFF trailing-comma falls through to last non-empty",
				headers: map[string]string{
					"X-Forwarded-For": "198.51.100.1, ",
					"X-Real-IP":       "192.0.2.99",
				},
				remote: "127.0.0.1:9999",
				wantIP: "198.51.100.1",
			},
			{
				name: "XFF entirely empty entries fall through to XRI",
				headers: map[string]string{
					"X-Forwarded-For": ", ,",
					"X-Real-IP":       "192.0.2.99",
				},
				remote: "127.0.0.1:9999",
				wantIP: "192.0.2.99",
			},
			{
				name: "XRI when no CF or XFF",
				headers: map[string]string{
					"X-Real-IP": "192.0.2.99",
				},
				remote: "127.0.0.1:9999",
				wantIP: "192.0.2.99",
			},
			{
				name:    "RemoteAddr IPv4 strips port",
				headers: nil,
				remote:  "127.0.0.1:9999",
				wantIP:  "127.0.0.1",
			},
			{
				name:    "RemoteAddr IPv6 strips brackets and port",
				headers: nil,
				remote:  "[2001:db8::1]:54321",
				wantIP:  "2001:db8::1",
			},
			{
				name:    "RemoteAddr loopback IPv6 strips brackets and port",
				headers: nil,
				remote:  "[::1]:9999",
				wantIP:  "::1",
			},
			{
				name:    "RemoteAddr without port falls back to raw value",
				headers: nil,
				remote:  "127.0.0.1",
				wantIP:  "127.0.0.1",
			},
			{
				name: "XFF mixed IPv4+IPv6 leftmost",
				headers: map[string]string{
					"X-Forwarded-For": "198.51.100.1, 2001:db8::dead",
				},
				remote: "127.0.0.1:9999",
				wantIP: "198.51.100.1",
			},
			{
				name: "CF value is trimmed of whitespace",
				headers: map[string]string{
					"CF-Connecting-IP": "  203.0.113.10  ",
				},
				remote: "127.0.0.1:9999",
				wantIP: "203.0.113.10",
			},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, "/c/token1", nil)
				for k, v := range tc.headers {
					r.Header.Set(k, v)
				}
				r.RemoteAddr = tc.remote
				evt, _, err := g.Trigger(context.Background(), tok, r)
				require.NoError(t, err)
				require.NotNil(t, evt)
				require.Equal(t, tc.wantIP, evt.SourceIP)
			})
		}
	})

	t.Run(
		"missing user agent and referer record as nil pointers",
		func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/c/token1", nil)
			r.Header.Del("User-Agent")
			r.Header.Del("Referer")
			r.Header.Set("CF-Connecting-IP", "203.0.113.5")

			evt, _, err := g.Trigger(context.Background(), tok, r)
			require.NoError(t, err)
			require.NotNil(t, evt)
			require.Nil(t, evt.UserAgent)
			require.Nil(t, evt.Referer)
		},
	)
}

func TestTrigger_ResponseBodyIsIndependentCopyPerCall(t *testing.T) {
	g := envfile.New()
	tok := newEnvfileToken("abc")
	r := httptest.NewRequest(http.MethodGet, "/c/abc", nil)

	_, resp1, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)
	_, resp2, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)

	resp1.Body[0] = 0x00
	require.Equal(t, byte(0x47), resp2.Body[0])
}

func TestTrigger_TokenNotFound_StillReturnsGIF(t *testing.T) {
	g := envfile.New()
	r := httptest.NewRequest(http.MethodGet, "/c/does-not-exist", nil)
	r.Header.Set("CF-Connecting-IP", "203.0.113.100")
	r.Header.Set("User-Agent", "curl/8.0.0")

	evt, resp, err := g.Trigger(context.Background(), nil, r)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, pixel.ContentType, resp.ContentType)
	require.Equal(t, pixel.Clone(), resp.Body)
	require.Nil(t, evt)
}
