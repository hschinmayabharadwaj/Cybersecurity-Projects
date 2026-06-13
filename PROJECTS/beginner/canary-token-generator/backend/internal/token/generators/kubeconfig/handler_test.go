// ©AngelaMos | 2026
// handler_test.go

package kubeconfig_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/kubeconfig"
)

const (
	cacheControlNoStoreValue = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaNoCacheValue       = "no-cache"
	expectedResponseMIME     = "application/json"
)

type k8sStatusResponse struct {
	Kind       string                 `json:"kind"`
	APIVersion string                 `json:"apiVersion"`
	Metadata   map[string]interface{} `json:"metadata"`
	Status     string                 `json:"status"`
	Message    string                 `json:"message"`
	Reason     string                 `json:"reason"`
	Code       int                    `json:"code"`
}

type kubectlExtra struct {
	KubectlPath   string `json:"kubectl_path"`
	KubectlMethod string `json:"kubectl_method"`
	KubectlQuery  string `json:"kubectl_query"`
	KubectlUA     string `json:"kubectl_ua"`
}

func parseStatus(t *testing.T, body []byte) k8sStatusResponse {
	t.Helper()
	var s k8sStatusResponse
	require.NoError(
		t,
		json.Unmarshal(body, &s),
		"response body must be valid Kubernetes Status JSON",
	)
	return s
}

func parseKubectlExtra(t *testing.T, raw json.RawMessage) kubectlExtra {
	t.Helper()
	var k kubectlExtra
	require.NoError(t, json.Unmarshal(raw, &k))
	return k
}

func TestTrigger_ResponseStatusCodeIs403(t *testing.T) {
	g := kubeconfig.New()
	tok := newKubeconfigToken("abc")
	r := httptest.NewRequest(http.MethodGet, "/k/abc/api/v1/pods", nil)

	_, resp, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestTrigger_ResponseContentTypeIsJSON(t *testing.T) {
	g := kubeconfig.New()
	tok := newKubeconfigToken("abc")
	r := httptest.NewRequest(http.MethodGet, "/k/abc/api/v1/pods", nil)

	_, resp, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)
	require.Equal(t, expectedResponseMIME, resp.ContentType)
}

func TestTrigger_CacheHeadersSet(t *testing.T) {
	g := kubeconfig.New()
	tok := newKubeconfigToken("abc")
	r := httptest.NewRequest(http.MethodGet, "/k/abc/api/v1/pods", nil)

	_, resp, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)
	require.Equal(
		t,
		cacheControlNoStoreValue,
		resp.ExtraHeaders["Cache-Control"],
	)
	require.Equal(t, pragmaNoCacheValue, resp.ExtraHeaders["Pragma"])
}

func TestTrigger_ResponseIsValidKubernetesStatus(t *testing.T) {
	g := kubeconfig.New()
	tok := newKubeconfigToken("abc")
	r := httptest.NewRequest(http.MethodGet, "/k/abc/api/v1/pods", nil)

	_, resp, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)

	s := parseStatus(t, resp.Body)
	require.Equal(t, "Status", s.Kind)
	require.Equal(t, "v1", s.APIVersion)
	require.NotNil(t, s.Metadata)
	require.Empty(t, s.Metadata, "metadata must be empty object {}")
	require.Equal(t, "Failure", s.Status)
	require.Equal(t, "Forbidden", s.Reason)
	require.Equal(t, http.StatusForbidden, s.Code)
}

func TestTrigger_MessageUsesPathLastSegmentAsResource(t *testing.T) {
	g := kubeconfig.New()
	tok := newKubeconfigToken("abc")

	cases := []struct {
		name     string
		path     string
		wantWord string
	}{
		{
			name:     "pods endpoint",
			path:     "/k/abc/api/v1/namespaces/default/pods",
			wantWord: "pods",
		},
		{
			name:     "secrets endpoint",
			path:     "/k/abc/api/v1/secrets",
			wantWord: "secrets",
		},
		{
			name:     "single-resource get",
			path:     "/k/abc/api/v1/namespaces/default/pods/web-1",
			wantWord: "web-1",
		},
		{
			name:     "api version probe",
			path:     "/k/abc/api/v1",
			wantWord: "v1",
		},
		{
			name:     "trailing slash path falls back to default",
			path:     "/k/abc/",
			wantWord: "abc",
		},
		{
			name:     "non-resource healthz probe",
			path:     "/k/abc/healthz",
			wantWord: "healthz",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			_, resp, err := g.Trigger(context.Background(), tok, r)
			require.NoError(t, err)
			s := parseStatus(t, resp.Body)
			require.Contains(
				t,
				s.Message,
				tc.wantWord+` is forbidden`,
				"message must lead with the resource name",
			)
			require.Contains(
				t,
				s.Message,
				`resource "`+tc.wantWord+`"`,
				"message must repeat the resource name in the resource clause",
			)
		})
	}
}

func TestTrigger_MessageVerbDerivedFromHTTPMethod(t *testing.T) {
	g := kubeconfig.New()
	tok := newKubeconfigToken("abc")

	cases := []struct {
		method   string
		wantVerb string
	}{
		{http.MethodGet, "list"},
		{http.MethodHead, "list"},
		{http.MethodPost, "create"},
		{http.MethodPut, "update"},
		{http.MethodPatch, "patch"},
		{http.MethodDelete, "delete"},
		{http.MethodOptions, "list"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.method, func(t *testing.T) {
			r := httptest.NewRequest(
				tc.method,
				"/k/abc/api/v1/pods",
				nil,
			)
			_, resp, err := g.Trigger(context.Background(), tok, r)
			require.NoError(t, err)
			s := parseStatus(t, resp.Body)
			require.Contains(
				t,
				s.Message,
				`cannot `+tc.wantVerb+` resource`,
				"message must use the verb mapped from the HTTP method",
			)
		})
	}
}

func TestTrigger_MessageImpersonatesAnonymousUser(t *testing.T) {
	g := kubeconfig.New()
	tok := newKubeconfigToken("abc")
	r := httptest.NewRequest(http.MethodGet, "/k/abc/api/v1/pods", nil)

	_, resp, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)

	s := parseStatus(t, resp.Body)
	require.Contains(
		t,
		s.Message,
		`User "system:anonymous"`,
		"message must impersonate the anonymous user for verisimilitude",
	)
}

func TestTrigger_RecordsEventWithRequestMetadata(t *testing.T) {
	g := kubeconfig.New()
	tok := newKubeconfigToken("token1")

	t.Run(
		"captures token id, source ip, user agent, referer",
		func(t *testing.T) {
			r := httptest.NewRequest(
				http.MethodGet,
				"/k/token1/api/v1/pods?watch=true",
				nil,
			)
			r.Header.Set("CF-Connecting-IP", "203.0.113.50")
			r.Header.Set(
				"User-Agent",
				"kubectl/v1.30.0 (linux/amd64) kubernetes/9b7f2dd",
			)
			r.Header.Set("Referer", "https://victim.example.com/dashboard")

			evt, _, err := g.Trigger(context.Background(), tok, r)
			require.NoError(t, err)
			require.NotNil(t, evt)
			require.Equal(t, "token1", evt.TokenID)
			require.Equal(t, "203.0.113.50", evt.SourceIP)
			require.NotNil(t, evt.UserAgent)
			require.Equal(
				t,
				"kubectl/v1.30.0 (linux/amd64) kubernetes/9b7f2dd",
				*evt.UserAgent,
			)
			require.NotNil(t, evt.Referer)
			require.Equal(
				t,
				"https://victim.example.com/dashboard",
				*evt.Referer,
			)
		},
	)

	t.Run("kubectl_* extra captured", func(t *testing.T) {
		r := httptest.NewRequest(
			http.MethodPost,
			"/k/token1/api/v1/namespaces/default/pods?dryRun=All",
			nil,
		)
		r.Header.Set("CF-Connecting-IP", "203.0.113.50")
		r.Header.Set("User-Agent", "kubectl/v1.30.0")

		evt, _, err := g.Trigger(context.Background(), tok, r)
		require.NoError(t, err)
		require.NotNil(t, evt)

		extra := parseKubectlExtra(t, evt.Extra)
		require.Equal(
			t,
			"/k/token1/api/v1/namespaces/default/pods",
			extra.KubectlPath,
		)
		require.Equal(t, http.MethodPost, extra.KubectlMethod)
		require.Equal(t, "dryRun=All", extra.KubectlQuery)
		require.Equal(t, "kubectl/v1.30.0", extra.KubectlUA)
	})

	t.Run("missing query is empty string in extra", func(t *testing.T) {
		r := httptest.NewRequest(
			http.MethodGet,
			"/k/token1/api/v1/pods",
			nil,
		)
		evt, _, err := g.Trigger(context.Background(), tok, r)
		require.NoError(t, err)
		extra := parseKubectlExtra(t, evt.Extra)
		require.Empty(t, extra.KubectlQuery)
	})

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
				r := httptest.NewRequest(
					http.MethodGet,
					"/k/token1/api/v1/pods",
					nil,
				)
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
			r := httptest.NewRequest(
				http.MethodGet,
				"/k/token1/api/v1/pods",
				nil,
			)
			r.Header.Del("User-Agent")
			r.Header.Del("Referer")
			r.Header.Set("CF-Connecting-IP", "203.0.113.5")

			evt, _, err := g.Trigger(context.Background(), tok, r)
			require.NoError(t, err)
			require.NotNil(t, evt)
			require.Nil(
				t,
				evt.UserAgent,
				"absent user agent must map to nil, not empty string",
			)
			require.Nil(
				t,
				evt.Referer,
				"absent referer must map to nil, not empty string",
			)
		},
	)
}

func TestTrigger_TokenNotFound_StillReturns403(t *testing.T) {
	g := kubeconfig.New()
	r := httptest.NewRequest(
		http.MethodGet,
		"/k/does-not-exist/api/v1/pods",
		nil,
	)
	r.Header.Set("CF-Connecting-IP", "203.0.113.100")
	r.Header.Set("User-Agent", "kubectl/v1.30.0")

	evt, resp, err := g.Trigger(context.Background(), nil, r)
	require.NoError(
		t,
		err,
		"nil-token path must not error (spec §8.5 defense-in-depth)",
	)
	require.NotNil(t, resp)
	require.Equal(
		t,
		http.StatusForbidden,
		resp.StatusCode,
		"nil-token still returns 403 so attackers cannot distinguish valid vs invalid tokens",
	)
	require.Equal(t, expectedResponseMIME, resp.ContentType)
	require.NotEmpty(t, resp.Body)

	s := parseStatus(t, resp.Body)
	require.Equal(t, "Status", s.Kind)
	require.Equal(t, "Failure", s.Status)

	require.Nil(
		t,
		evt,
		"nil-token path returns nil event so the handler cannot persist a row with empty TokenID (FK violation)",
	)
}

func TestTrigger_NilTokenResponseShapeMatchesValidToken(t *testing.T) {
	g := kubeconfig.New()
	tok := newKubeconfigToken("real-token")

	r1 := httptest.NewRequest(
		http.MethodGet,
		"/k/real-token/api/v1/pods",
		nil,
	)
	r2 := httptest.NewRequest(
		http.MethodGet,
		"/k/does-not-exist/api/v1/pods",
		nil,
	)

	_, respValid, err := g.Trigger(context.Background(), tok, r1)
	require.NoError(t, err)
	_, respMissing, err := g.Trigger(context.Background(), nil, r2)
	require.NoError(t, err)

	sValid := parseStatus(t, respValid.Body)
	sMissing := parseStatus(t, respMissing.Body)

	require.Equal(t, sValid.Kind, sMissing.Kind)
	require.Equal(t, sValid.APIVersion, sMissing.APIVersion)
	require.Equal(t, sValid.Status, sMissing.Status)
	require.Equal(t, sValid.Reason, sMissing.Reason)
	require.Equal(t, sValid.Code, sMissing.Code)
	require.Equal(
		t,
		respValid.StatusCode,
		respMissing.StatusCode,
		"HTTP status code must be identical so attackers cannot probe token validity by response code",
	)
}
