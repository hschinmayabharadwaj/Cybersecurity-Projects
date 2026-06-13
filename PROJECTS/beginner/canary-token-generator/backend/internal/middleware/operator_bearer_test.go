// ©AngelaMos | 2026
// operator_bearer_test.go

package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/middleware"
)

const (
	opTokenCorrect = "s3cr3t-op-token-xyz"
	opTokenWrong   = "s3cr3t-op-token-XYZ"
)

func opNextHandler(calls *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTeapot)
		if _, err := w.Write([]byte("ok")); err != nil {
			return
		}
	})
}

func TestOperatorBearer_TableDriven(t *testing.T) {
	tests := []struct {
		name           string
		configuredTok  string
		authHeader     string
		setHeader      bool
		wantStatus     int
		wantBodyPrefix string
		wantNextCalled bool
	}{
		{
			name:           "missing Authorization header returns 404",
			configuredTok:  opTokenCorrect,
			setHeader:      false,
			wantStatus:     http.StatusNotFound,
			wantBodyPrefix: "404",
			wantNextCalled: false,
		},
		{
			name:           "empty Authorization header returns 404",
			configuredTok:  opTokenCorrect,
			authHeader:     "",
			setHeader:      true,
			wantStatus:     http.StatusNotFound,
			wantNextCalled: false,
		},
		{
			name:           "wrong scheme Basic returns 404",
			configuredTok:  opTokenCorrect,
			authHeader:     "Basic " + opTokenCorrect,
			setHeader:      true,
			wantStatus:     http.StatusNotFound,
			wantNextCalled: false,
		},
		{
			name:           "lowercase bearer returns 404 (scheme is case-sensitive)",
			configuredTok:  opTokenCorrect,
			authHeader:     "bearer " + opTokenCorrect,
			setHeader:      true,
			wantStatus:     http.StatusNotFound,
			wantNextCalled: false,
		},
		{
			name:           "Bearer prefix with no token returns 404",
			configuredTok:  opTokenCorrect,
			authHeader:     "Bearer ",
			setHeader:      true,
			wantStatus:     http.StatusNotFound,
			wantNextCalled: false,
		},
		{
			name:           "Bearer with no trailing space returns 404",
			configuredTok:  opTokenCorrect,
			authHeader:     "Bearer" + opTokenCorrect,
			setHeader:      true,
			wantStatus:     http.StatusNotFound,
			wantNextCalled: false,
		},
		{
			name:           "wrong token of equal length returns 404",
			configuredTok:  opTokenCorrect,
			authHeader:     "Bearer " + opTokenWrong,
			setHeader:      true,
			wantStatus:     http.StatusNotFound,
			wantNextCalled: false,
		},
		{
			name:           "wrong token of different length returns 404",
			configuredTok:  opTokenCorrect,
			authHeader:     "Bearer nope",
			setHeader:      true,
			wantStatus:     http.StatusNotFound,
			wantNextCalled: false,
		},
		{
			name:           "correct token passes through to next",
			configuredTok:  opTokenCorrect,
			authHeader:     "Bearer " + opTokenCorrect,
			setHeader:      true,
			wantStatus:     http.StatusTeapot,
			wantBodyPrefix: "ok",
			wantNextCalled: true,
		},
		{
			name:           "empty configured token rejects all requests including matching empty",
			configuredTok:  "",
			authHeader:     "Bearer ",
			setHeader:      true,
			wantStatus:     http.StatusNotFound,
			wantNextCalled: false,
		},
		{
			name:           "empty configured token rejects even a Bearer-with-payload",
			configuredTok:  "",
			authHeader:     "Bearer anything",
			setHeader:      true,
			wantStatus:     http.StatusNotFound,
			wantNextCalled: false,
		},
		{
			name:           "extra whitespace inside token is not trimmed",
			configuredTok:  opTokenCorrect,
			authHeader:     "Bearer  " + opTokenCorrect,
			setHeader:      true,
			wantStatus:     http.StatusNotFound,
			wantNextCalled: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			h := middleware.OperatorBearer(
				tc.configuredTok,
			)(
				opNextHandler(&calls),
			)

			r := httptest.NewRequest(http.MethodGet, "/admin/x", nil)
			if tc.setHeader {
				r.Header.Set("Authorization", tc.authHeader)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)

			require.Equal(t, tc.wantStatus, w.Code)
			if tc.wantNextCalled {
				require.Equal(t, int32(1), calls.Load())
			} else {
				require.Equal(t, int32(0), calls.Load(),
					"next handler must not be invoked on auth failure")
			}
			if tc.wantBodyPrefix != "" {
				require.Contains(t, w.Body.String(), tc.wantBodyPrefix)
			}
		})
	}
}

func TestOperatorBearer_NoWWWAuthenticateHeader(t *testing.T) {
	var calls atomic.Int32
	h := middleware.OperatorBearer(opTokenCorrect)(opNextHandler(&calls))

	r := httptest.NewRequest(http.MethodGet, "/admin/x", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
	require.Empty(
		t,
		w.Header().Get("WWW-Authenticate"),
		"404 hides endpoint existence; WWW-Authenticate would leak the auth scheme",
	)
}
