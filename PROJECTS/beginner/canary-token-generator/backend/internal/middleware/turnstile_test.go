// ©AngelaMos | 2026
// turnstile_test.go

package middleware_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/middleware"
)

type fakeVerifier struct {
	calls       atomic.Int32
	lastToken   atomic.Value
	lastFP      atomic.Value
	returnError error
}

func (f *fakeVerifier) Verify(_ context.Context, token, fp string) error {
	f.calls.Add(1)
	f.lastToken.Store(token)
	f.lastFP.Store(fp)
	return f.returnError
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(body); err != nil {
			return
		}
	})
}

func TestTurnstileVerify_HeaderTokenPasses(t *testing.T) {
	v := &fakeVerifier{}
	h := middleware.TurnstileVerify(v)(okHandler())

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("CF-Turnstile-Response", "header-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, int32(1), v.calls.Load())
	require.Equal(t, "header-token", v.lastToken.Load())
}

func TestTurnstileVerify_BodyTokenPasses(t *testing.T) {
	v := &fakeVerifier{}
	h := middleware.TurnstileVerify(v)(okHandler())

	r := httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"cf_turnstile_response":"body-token","other":1}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "body-token", v.lastToken.Load())
}

func TestTurnstileVerify_BodyPreservedForDownstream(t *testing.T) {
	v := &fakeVerifier{}
	h := middleware.TurnstileVerify(v)(okHandler())

	body := `{"cf_turnstile_response":"t","foo":"bar"}`
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, body, w.Body.String(),
		"downstream handler must still read the original body")
}

func TestTurnstileVerify_FailureReturns400(t *testing.T) {
	v := &fakeVerifier{returnError: errors.New("bad")}
	h := middleware.TurnstileVerify(v)(okHandler())

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("CF-Turnstile-Response", "tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"TURNSTILE_FAILED"`)
}

func TestTurnstileVerify_HeaderWinsOverBody(t *testing.T) {
	v := &fakeVerifier{}
	h := middleware.TurnstileVerify(v)(okHandler())

	r := httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"cf_turnstile_response":"body-token"}`))
	r.Header.Set("CF-Turnstile-Response", "header-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, "header-token", v.lastToken.Load())
}

func TestTurnstileVerify_NoTokenStillCallsVerifier(t *testing.T) {
	v := &fakeVerifier{}
	h := middleware.TurnstileVerify(v)(okHandler())

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, int32(1), v.calls.Load())
	require.Empty(t, v.lastToken.Load())
}
