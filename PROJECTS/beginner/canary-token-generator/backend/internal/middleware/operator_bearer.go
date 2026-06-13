// ©AngelaMos | 2026
// operator_bearer.go

package middleware

import (
	"crypto/subtle"
	"net/http"
)

const bearerPrefix = "Bearer "

func OperatorBearer(token string) func(http.Handler) http.Handler {
	expected := []byte(token)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(expected) == 0 {
				http.NotFound(w, r)
				return
			}
			auth := r.Header.Get("Authorization")
			if len(auth) <= len(bearerPrefix) ||
				auth[:len(bearerPrefix)] != bearerPrefix {
				http.NotFound(w, r)
				return
			}
			supplied := []byte(auth[len(bearerPrefix):])
			if subtle.ConstantTimeCompare(supplied, expected) != 1 {
				http.NotFound(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
