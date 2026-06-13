// ©AngelaMos | 2026
// verifier_test.go

package turnstile_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/turnstile"
)

type fakeRedis struct {
	store map[string]string
}

func (f *fakeRedis) Get(_ context.Context, key string) *redis.StringCmd {
	cmd := redis.NewStringCmd(context.Background())
	if v, ok := f.store[key]; ok {
		cmd.SetVal(v)
	} else {
		cmd.SetErr(redis.Nil)
	}
	return cmd
}

func (f *fakeRedis) SetEx(
	_ context.Context,
	key string,
	value any,
	_ time.Duration,
) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(context.Background())
	if f.store == nil {
		f.store = make(map[string]string)
	}
	if s, ok := value.(string); ok {
		f.store[key] = s
	}
	cmd.SetVal("OK")
	return cmd
}

func startMockSiteverify(
	t *testing.T,
	success bool,
	errorCodes []string,
) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			var body string
			if success {
				body = `{"success":true}`
			} else {
				body = `{"success":false,"error-codes":[`
				for i, c := range errorCodes {
					if i > 0 {
						body += ","
					}
					body += `"` + c + `"`
				}
				body += `]}`
			}
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write mock: %v", err)
			}
		}),
	)
	t.Cleanup(srv.Close)
	return srv.URL, &hits
}

func TestVerifier_EmptySecretBypasses(t *testing.T) {
	v := turnstile.NewVerifier(turnstile.Config{}, &fakeRedis{})
	require.NoError(t, v.Verify(context.Background(), "irrelevant", "fp"))
}

func TestVerifier_EmptyTokenReturnsError(t *testing.T) {
	v := turnstile.NewVerifier(turnstile.Config{SecretKey: "s"}, &fakeRedis{})
	err := v.Verify(context.Background(), "  ", "fp")
	require.ErrorIs(t, err, turnstile.ErrEmptyToken)
}

func TestVerifier_SuccessCachesByFingerprint(t *testing.T) {
	url, hits := startMockSiteverify(t, true, nil)
	r := &fakeRedis{}
	v := turnstile.NewVerifier(turnstile.Config{
		SecretKey: "secret",
		VerifyURL: url,
	}, r)

	require.NoError(t, v.Verify(context.Background(), "tok", "fp1"))
	require.Equal(t, int32(1), hits.Load())

	require.NoError(t, v.Verify(context.Background(), "tok", "fp1"))
	require.Equal(
		t,
		int32(1),
		hits.Load(),
		"cache hit must skip siteverify call",
	)
}

func TestVerifier_CacheMissForDifferentFingerprint(t *testing.T) {
	url, hits := startMockSiteverify(t, true, nil)
	v := turnstile.NewVerifier(turnstile.Config{
		SecretKey: "secret",
		VerifyURL: url,
	}, &fakeRedis{})

	require.NoError(t, v.Verify(context.Background(), "tok", "fp1"))
	require.NoError(t, v.Verify(context.Background(), "tok", "fp2"))
	require.Equal(t, int32(2), hits.Load())
}

func TestVerifier_FailedSiteverifyReturnsErrVerifyFailed(t *testing.T) {
	url, _ := startMockSiteverify(t, false, []string{"invalid-input-response"})
	v := turnstile.NewVerifier(turnstile.Config{
		SecretKey: "secret",
		VerifyURL: url,
	}, &fakeRedis{})

	err := v.Verify(context.Background(), "tok", "fp")
	require.Error(t, err)
	require.ErrorIs(t, err, turnstile.ErrVerifyFailed)
}

func TestVerifier_NilRedisStillWorks(t *testing.T) {
	url, hits := startMockSiteverify(t, true, nil)
	v := turnstile.NewVerifier(turnstile.Config{
		SecretKey: "secret",
		VerifyURL: url,
	}, nil)

	require.NoError(t, v.Verify(context.Background(), "tok", "fp"))
	require.NoError(t, v.Verify(context.Background(), "tok", "fp"))
	require.Equal(t, int32(2), hits.Load(), "without redis there is no caching")
}

func TestVerifier_NetworkErrorIsWrapped(t *testing.T) {
	v := turnstile.NewVerifier(turnstile.Config{
		SecretKey: "secret",
		VerifyURL: "http://127.0.0.1:1/never",
		Client:    &http.Client{Timeout: 100 * time.Millisecond},
	}, &fakeRedis{})

	err := v.Verify(context.Background(), "tok", "fp")
	require.Error(t, err)
	require.NotErrorIs(t, err, turnstile.ErrVerifyFailed)
}
