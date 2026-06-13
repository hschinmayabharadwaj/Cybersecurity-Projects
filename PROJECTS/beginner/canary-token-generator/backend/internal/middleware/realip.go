// ©AngelaMos | 2026
// realip.go

package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
)

const (
	headerCFConnectingIP = "CF-Connecting-IP"
	headerXForwardedFor  = "X-Forwarded-For"
	headerXRealIP        = "X-Real-IP"
)

type proxyTrustState struct {
	cidrs []*net.IPNet
}

var trustedProxies atomic.Pointer[proxyTrustState]

func SetTrustedProxyCIDRs(cidrs []string) error {
	parsed := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		trimmed := strings.TrimSpace(c)
		if trimmed == "" {
			continue
		}
		_, n, err := net.ParseCIDR(trimmed)
		if err != nil {
			return fmt.Errorf("trusted proxy cidr %q: %w", c, err)
		}
		parsed = append(parsed, n)
	}
	trustedProxies.Store(&proxyTrustState{cidrs: parsed})
	return nil
}

func ClearTrustedProxyCIDRs() {
	trustedProxies.Store(nil)
}

func isTrustedProxy(remoteAddr string) bool {
	state := trustedProxies.Load()
	if state == nil {
		return true
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range state.cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func RealIP(r *http.Request) string {
	if isTrustedProxy(r.RemoteAddr) {
		if v := strings.TrimSpace(
			r.Header.Get(headerCFConnectingIP),
		); v != "" {
			return v
		}
		if v := firstNonEmptyXFF(
			r.Header.Get(headerXForwardedFor),
		); v != "" {
			return v
		}
		if v := strings.TrimSpace(r.Header.Get(headerXRealIP)); v != "" {
			return v
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func OptionalHeader(v string) *string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return &v
}

func firstNonEmptyXFF(header string) string {
	if header == "" {
		return ""
	}
	for _, p := range strings.Split(header, ",") {
		if v := strings.TrimSpace(p); v != "" {
			return v
		}
	}
	return ""
}
