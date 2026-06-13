// ©AngelaMos | 2026
// sender_test.go

package webhook_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/notify/webhook"
)

const (
	testTokenID  = "tokwh01abcde"
	testManageID = "abcd1111-2222-3333-4444-555555555555"
)

func sampleEvent() *event.Event {
	ua := "TestUA/1.0"
	city := "Toronto"
	country := "CA"
	asnOrg := "Test, Inc."
	asn := 12345
	return &event.Event{
		ID:          7,
		TokenID:     testTokenID,
		TriggeredAt: time.Date(2026, 5, 14, 12, 30, 0, 0, time.UTC),
		SourceIP:    "203.0.113.45",
		UserAgent:   &ua,
		GeoCity:     &city,
		GeoCountry:  &country,
		GeoASN:      &asn,
		GeoASNOrg:   &asnOrg,
		Extra:       json.RawMessage(`{"custom":"value"}`),
	}
}

func sampleInfo(webhookURL string) event.NotifyInfo {
	return event.NotifyInfo{
		TokenID:      testTokenID,
		ManageID:     testManageID,
		Type:         "envfile",
		Memo:         "prod-creds",
		AlertChannel: "webhook",
		WebhookURL:   webhookURL,
	}
}

type capture struct {
	calls    atomic.Int32
	lastBody atomic.Value
	lastSig  atomic.Value
}

func newCaptureServer(
	t *testing.T,
	handler http.HandlerFunc,
) (*httptest.Server, *capture) {
	t.Helper()
	c := &capture{}
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.calls.Add(1)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Logf("read body: %v", err)
				return
			}
			c.lastBody.Store(body)
			c.lastSig.Store(r.Header.Get("X-Canary-Signature"))
			handler(w, r)
		}),
	)
	t.Cleanup(srv.Close)
	return srv, c
}

func loadBody(t *testing.T, c *capture) []byte {
	t.Helper()
	raw, ok := c.lastBody.Load().([]byte)
	require.True(t, ok, "no body captured")
	return raw
}

func newSender(t *testing.T, opts ...webhook.Option) *webhook.Sender {
	t.Helper()
	return webhook.NewSender(webhook.Config{
		ManageURL:         "https://canary.example.com",
		AllowPrivateHosts: true,
	}, opts...)
}

func newStrictSender(t *testing.T) *webhook.Sender {
	t.Helper()
	return webhook.NewSender(webhook.Config{
		ManageURL: "https://canary.example.com",
	})
}

func TestSender_Channel(t *testing.T) {
	t.Parallel()
	require.Equal(t, "webhook", newSender(t).Channel())
}

func TestSender_Send_PostsToProvidedURL(t *testing.T) {
	t.Parallel()
	srv, cap := newCaptureServer(
		t,
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		},
	)
	s := newSender(t)
	require.NoError(
		t,
		s.Send(context.Background(), sampleInfo(srv.URL), sampleEvent()),
	)
	require.Equal(t, int32(1), cap.calls.Load())
}

func TestSender_Send_BodyEnvelopeShape(t *testing.T) {
	t.Parallel()
	srv, cap := newCaptureServer(
		t,
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
	)
	s := newSender(t)
	require.NoError(
		t,
		s.Send(context.Background(), sampleInfo(srv.URL), sampleEvent()),
	)

	var env map[string]any
	require.NoError(t, json.Unmarshal(loadBody(t, cap), &env))

	require.Equal(t, "1", env["version"])
	require.Equal(t, "canary.triggered", env["event"])

	tok, ok := env["token"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, testTokenID, tok["id"])
	require.Equal(t, "envfile", tok["type"])
	require.Equal(t, "prod-creds", tok["memo"])
	require.Equal(
		t,
		"https://canary.example.com/m/"+testManageID,
		tok["manage_url"],
	)

	trig, ok := env["trigger"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "203.0.113.45", trig["source_ip"])
	require.Equal(t, "TestUA/1.0", trig["user_agent"])
	require.NotEmpty(t, trig["triggered_at"])

	geo, ok := trig["geo"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "CA", geo["country"])
	require.Equal(t, "Toronto", geo["city"])
	require.Equal(t, "Test, Inc.", geo["asn_org"])

	extra, ok := trig["extra"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "value", extra["custom"])
}

func TestSender_Send_NoSignatureWithoutSecret(t *testing.T) {
	t.Parallel()
	srv, cap := newCaptureServer(
		t,
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
	)
	s := newSender(t)
	require.NoError(
		t,
		s.Send(context.Background(), sampleInfo(srv.URL), sampleEvent()),
	)
	require.Empty(t, cap.lastSig.Load())
}

func TestSender_Send_HMACSignatureWhenSecretSet(t *testing.T) {
	t.Parallel()
	const secret = "topsecret"
	srv, cap := newCaptureServer(
		t,
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
	)
	s := webhook.NewSender(webhook.Config{
		ManageURL:         "https://canary.example.com",
		HMACSecret:        secret,
		AllowPrivateHosts: true,
	})
	require.NoError(
		t,
		s.Send(context.Background(), sampleInfo(srv.URL), sampleEvent()),
	)

	body := loadBody(t, cap)
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write(body); err != nil {
		t.Fatal(err)
	}
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	require.Equal(t, want, cap.lastSig.Load())
}

func TestSender_Send_EmptyURLReturnsConfigErr(t *testing.T) {
	t.Parallel()
	s := newSender(t)
	err := s.Send(context.Background(), sampleInfo(""), sampleEvent())
	require.ErrorIs(t, err, webhook.ErrChannelNotConfigured)
}

func TestSender_Send_RejectsNonHTTPScheme(t *testing.T) {
	t.Parallel()
	cases := []string{
		"ftp://example.com/hook",
		"file:///etc/passwd",
		"javascript:alert(1)",
		"not-a-url",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			s := newSender(t)
			err := s.Send(context.Background(), sampleInfo(u), sampleEvent())
			require.ErrorIs(t, err, webhook.ErrInvalidWebhookURL)
		})
	}
}

func TestSender_Send_RejectsURLWithoutHost(t *testing.T) {
	t.Parallel()
	s := newSender(t)
	err := s.Send(
		context.Background(),
		sampleInfo("http:///nohost"),
		sampleEvent(),
	)
	require.ErrorIs(t, err, webhook.ErrInvalidWebhookURL)
}

func TestSender_Send_RejectsURLWithUserInfo(t *testing.T) {
	t.Parallel()
	s := newSender(t)
	err := s.Send(
		context.Background(),
		sampleInfo("https://user:pass@example.com/h"),
		sampleEvent(),
	)
	require.ErrorIs(t, err, webhook.ErrInvalidWebhookURL)
}

func TestSender_Send_RetriesOn5xxThenSucceeds(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			n := attempts.Add(1)
			if n == 1 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusOK)
		}),
	)
	t.Cleanup(srv.Close)
	s := newSender(t,
		webhook.WithMaxTries(3),
		webhook.WithMaxElapsed(2*time.Second),
		webhook.WithInitialInterval(5*time.Millisecond),
	)
	require.NoError(
		t,
		s.Send(context.Background(), sampleInfo(srv.URL), sampleEvent()),
	)
	require.Equal(t, int32(2), attempts.Load())
}

func TestSender_Send_PermanentOn4xx(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts.Add(1)
			w.WriteHeader(http.StatusForbidden)
		}),
	)
	t.Cleanup(srv.Close)
	s := newSender(t,
		webhook.WithMaxTries(5),
		webhook.WithInitialInterval(5*time.Millisecond),
	)
	err := s.Send(context.Background(), sampleInfo(srv.URL), sampleEvent())
	require.Error(t, err)
	require.Equal(t, int32(1), attempts.Load())
}

func TestSender_Send_AbortsAfterMaxTries(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
		}),
	)
	t.Cleanup(srv.Close)
	s := newSender(t,
		webhook.WithMaxTries(3),
		webhook.WithMaxElapsed(5*time.Second),
		webhook.WithInitialInterval(2*time.Millisecond),
	)
	err := s.Send(context.Background(), sampleInfo(srv.URL), sampleEvent())
	require.Error(t, err)
	require.Equal(t, int32(3), attempts.Load())
}

func TestSender_Validate_BlocksPrivateHosts(t *testing.T) {
	t.Parallel()
	s := newStrictSender(t)
	cases := []string{
		"http://127.0.0.1/",
		"http://127.0.0.1:6379/",
		"http://10.0.0.1/",
		"http://10.255.255.255/",
		"http://172.16.0.1/",
		"http://172.31.255.255/",
		"http://192.168.1.1/",
		"http://169.254.169.254/latest/meta-data/",
		"http://100.64.0.1/",
		"http://0.0.0.0/",
		"http://[::1]/",
		"http://[fd00::1]/",
		"http://[fe80::1]/",
	}
	for _, raw := range cases {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			err := s.Validate(raw)
			require.ErrorIsf(
				t,
				err,
				webhook.ErrBlockedHost,
				"expected ErrBlockedHost for %q",
				raw,
			)
		})
	}
}

func TestSender_Validate_AllowsPublicLiteralIPs(t *testing.T) {
	t.Parallel()
	s := newStrictSender(t)
	cases := []string{
		"https://8.8.8.8/",
		"https://1.1.1.1/",
		"http://203.0.113.45:8080/hook",
		"https://[2001:db8::1]/",
	}
	for _, raw := range cases {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			require.NoError(t, s.Validate(raw))
		})
	}
}

func TestSender_Send_BlocksPrivateHostByDefault(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	t.Cleanup(srv.Close)

	s := newStrictSender(t)
	err := s.Send(context.Background(), sampleInfo(srv.URL), sampleEvent())
	require.ErrorIs(
		t,
		err,
		webhook.ErrBlockedHost,
		"strict sender must refuse to send to loopback URL",
	)
}

func TestSender_Send_RespectsContextCancel(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(
		http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			time.Sleep(2 * time.Second)
		}),
	)
	t.Cleanup(srv.Close)
	s := newSender(t,
		webhook.WithMaxTries(3),
		webhook.WithInitialInterval(5*time.Millisecond),
	)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		100*time.Millisecond,
	)
	defer cancel()
	err := s.Send(ctx, sampleInfo(srv.URL), sampleEvent())
	require.Error(t, err)
	require.True(
		t,
		errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, context.Canceled),
		"expected context error, got %v",
		err,
	)
}
