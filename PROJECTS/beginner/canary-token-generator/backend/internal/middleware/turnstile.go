// ©AngelaMos | 2026
// turnstile.go

package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
)

const (
	turnstileHeaderName       = "CF-Turnstile-Response"
	turnstileBodyFieldName    = "cf_turnstile_response"
	turnstileMaxBodyBytes     = 1 * 1024 * 1024
	turnstileErrorContentType = "application/json"
	turnstileErrorBody        = `{"success":false,"error":{"code":"TURNSTILE_FAILED","message":"turnstile verification failed"}}`
)

type TurnstileVerifier interface {
	Verify(ctx context.Context, token, fingerprint string) error
}

func TurnstileVerify(v TurnstileVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := extractTurnstileToken(r)
			fp := ExtractFingerprint(r)

			if err := v.Verify(r.Context(), tokenStr, fp); err != nil {
				w.Header().Set("Content-Type", turnstileErrorContentType)
				w.WriteHeader(http.StatusBadRequest)
				if _, wErr := w.Write([]byte(turnstileErrorBody)); wErr != nil {
					return
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func extractTurnstileToken(r *http.Request) string {
	if v := r.Header.Get(turnstileHeaderName); v != "" {
		return v
	}
	if r.Body == nil {
		return ""
	}
	limited := io.LimitReader(r.Body, turnstileMaxBodyBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	if s, ok := m[turnstileBodyFieldName].(string); ok {
		return s
	}
	return ""
}
