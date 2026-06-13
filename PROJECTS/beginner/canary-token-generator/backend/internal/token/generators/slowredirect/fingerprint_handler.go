// ©AngelaMos | 2026
// fingerprint_handler.go

package slowredirect

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/middleware"
)

const (
	fingerprintWindow     = 30 * time.Second
	fingerprintMaxBytes   = 64 * 1024
	urlParamTokenID       = "id"
	headerContentType     = "Content-Type"
	contentTypeJSONPrefix = "application/json"
)

type FingerprintAttacher interface {
	AttachFingerprint(
		ctx context.Context,
		tokenID, sourceIP string,
		fingerprint json.RawMessage,
		window time.Duration,
	) error
}

type FingerprintHandler struct {
	attacher FingerprintAttacher
	window   time.Duration
}

func NewFingerprintHandler(a FingerprintAttacher) *FingerprintHandler {
	return &FingerprintHandler{
		attacher: a,
		window:   fingerprintWindow,
	}
}

func (h *FingerprintHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tokenID := chi.URLParam(r, urlParamTokenID)
	if tokenID == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if !strings.HasPrefix(
		strings.ToLower(r.Header.Get(headerContentType)),
		contentTypeJSONPrefix,
	) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, fingerprintMaxBytes))
	if err != nil || len(body) == 0 || !json.Valid(body) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := h.attacher.AttachFingerprint(
		ctx,
		tokenID,
		middleware.RealIP(r),
		json.RawMessage(body),
		h.window,
	); err != nil && !errors.Is(err, event.ErrNotFound) {
		slog.WarnContext(ctx, "attach fingerprint failed",
			"token_id", tokenID,
			"error", err,
		)
	}
	w.WriteHeader(http.StatusNoContent)
}
