// ©AngelaMos | 2026
// verifier.go

package turnstile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	DefaultVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

	cacheKeyPrefix    = "turnstile:fp:"
	cacheTTL          = 5 * time.Minute
	verifyTimeout     = 10 * time.Second
	cachedSuccessFlag = "ok"

	contentTypeForm = "application/x-www-form-urlencoded"
)

var (
	ErrVerifyFailed = errors.New("turnstile: verification failed")
	ErrEmptyToken   = errors.New("turnstile: empty response token")
)

type RedisClient interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	SetEx(
		ctx context.Context,
		key string,
		value any,
		expiration time.Duration,
	) *redis.StatusCmd
}

type Config struct {
	SecretKey string
	VerifyURL string
	Client    *http.Client
}

type Verifier struct {
	secret    string
	verifyURL string
	client    *http.Client
	rdb       RedisClient
}

func NewVerifier(cfg Config, rdb RedisClient) *Verifier {
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: verifyTimeout}
	}
	verifyURL := cfg.VerifyURL
	if verifyURL == "" {
		verifyURL = DefaultVerifyURL
	}
	return &Verifier{
		secret:    cfg.SecretKey,
		verifyURL: verifyURL,
		client:    client,
		rdb:       rdb,
	}
}

func (v *Verifier) Verify(
	ctx context.Context,
	token, fingerprint string,
) error {
	if v.secret == "" {
		return nil
	}
	if strings.TrimSpace(token) == "" {
		return ErrEmptyToken
	}

	cacheKey := cacheKeyPrefix + fingerprint
	if v.rdb != nil {
		if cached, err := v.rdb.Get(ctx, cacheKey).Result(); err == nil &&
			cached == cachedSuccessFlag {
			return nil
		}
	}

	if err := v.callSiteverify(ctx, token); err != nil {
		return err
	}

	if v.rdb != nil {
		if cErr := v.rdb.SetEx(
			ctx,
			cacheKey,
			cachedSuccessFlag,
			cacheTTL,
		).Err(); cErr != nil {
			slog.WarnContext(ctx, "turnstile: cache set",
				"error", cErr, "fingerprint", fingerprint)
		}
	}
	return nil
}

func (v *Verifier) callSiteverify(ctx context.Context, token string) error {
	form := url.Values{"secret": {v.secret}, "response": {token}}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		v.verifyURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return fmt.Errorf("turnstile: build request: %w", err)
	}
	req.Header.Set("Content-Type", contentTypeForm)

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("turnstile: call siteverify: %w", err)
	}
	defer func() {
		if cErr := resp.Body.Close(); cErr != nil {
			slog.WarnContext(ctx, "turnstile: close body",
				"error", cErr)
		}
	}()

	var body struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("turnstile: decode response: %w", err)
	}
	if !body.Success {
		return fmt.Errorf("%w: %v", ErrVerifyFailed, body.ErrorCodes)
	}
	return nil
}
