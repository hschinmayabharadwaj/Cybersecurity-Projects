// ©AngelaMos | 2026
// service.go

package event

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	dedupKeyPrefix  = "dedup:trigger:"
	defaultDedupTTL = 15 * time.Minute
	dedupScanBatch  = 100
)

type Service struct {
	repo     Store
	tokens   TokenIncrementer
	rdb      *redis.Client
	notifier Notifier
	dedupTTL time.Duration
	logger   *slog.Logger
}

type ServiceConfig struct {
	DedupTTL time.Duration
	Logger   *slog.Logger
}

func NewService(
	repo Store,
	tokens TokenIncrementer,
	rdb *redis.Client,
	notifier Notifier,
	cfg ServiceConfig,
) *Service {
	if cfg.DedupTTL <= 0 {
		cfg.DedupTTL = defaultDedupTTL
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Service{
		repo:     repo,
		tokens:   tokens,
		rdb:      rdb,
		notifier: notifier,
		dedupTTL: cfg.DedupTTL,
		logger:   cfg.Logger,
	}
}

func DedupKey(tokenID, sourceIP string) string {
	return dedupKeyPrefix + tokenID + ":" + sourceIP
}

func (s *Service) Record(
	ctx context.Context,
	info NotifyInfo,
	evt *Event,
) error {
	if err := s.repo.Insert(ctx, evt); err != nil {
		return fmt.Errorf("insert event: %w", err)
	}

	if s.tokens != nil {
		if err := s.tokens.IncrementTriggerCount(
			ctx,
			info.TokenID,
		); err != nil {
			s.logger.WarnContext(ctx, "increment trigger count",
				"error", err, "token_id", info.TokenID)
		}
	}

	first := s.dedupGate(ctx, info.TokenID, evt.SourceIP)
	if !first {
		if err := s.repo.UpdateNotifyStatus(
			ctx, evt.ID, NotifyDeduped, nil,
		); err != nil {
			s.logger.WarnContext(ctx, "update notify status deduped",
				"error", err, "event_id", evt.ID)
		}
		return nil
	}

	if s.notifier != nil {
		s.notifier.Notify(info, evt)
	}
	return nil
}

func (s *Service) dedupGate(
	ctx context.Context,
	tokenID, sourceIP string,
) bool {
	if s.rdb == nil {
		return true
	}
	key := DedupKey(tokenID, sourceIP)
	set, err := s.rdb.SetNX(ctx, key, 1, s.dedupTTL).Result()
	if err != nil {
		s.logger.WarnContext(ctx, "dedup setnx failed (fail-open)",
			"error", err, "key", key)
		return true
	}
	if set {
		return true
	}
	if _, iErr := s.rdb.Incr(ctx, key).Result(); iErr != nil {
		s.logger.WarnContext(ctx, "dedup incr failed",
			"error", iErr, "key", key)
	}
	return false
}

func (s *Service) CountActiveDedup(
	ctx context.Context,
	tokenID string,
) (int64, error) {
	if s.rdb == nil {
		return 0, nil
	}
	pattern := dedupKeyPrefix + tokenID + ":*"
	var total int64
	var cursor uint64
	for {
		keys, next, err := s.rdb.Scan(
			ctx, cursor, pattern, dedupScanBatch,
		).Result()
		if err != nil {
			return 0, fmt.Errorf("dedup scan: %w", err)
		}
		for _, key := range keys {
			v, gErr := s.rdb.Get(ctx, key).Result()
			if errors.Is(gErr, redis.Nil) {
				continue
			}
			if gErr != nil {
				s.logger.WarnContext(ctx, "dedup count: get key",
					"error", gErr, "key", key)
				continue
			}
			n, pErr := strconv.ParseInt(v, 10, 64)
			if pErr != nil {
				continue
			}
			if n > 1 {
				total += n - 1
			}
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	return total, nil
}

func (s *Service) RunRetentionLoop(
	ctx context.Context,
	interval time.Duration,
	perTokenLimit int,
) {
	if interval <= 0 || perTokenLimit <= 0 {
		s.logger.WarnContext(ctx, "retention loop disabled (invalid config)",
			"interval", interval, "limit", perTokenLimit)
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.logger.InfoContext(ctx, "retention loop started",
		"interval", interval, "per_token_limit", perTokenLimit)

	for {
		select {
		case <-ctx.Done():
			s.logger.InfoContext(ctx, "retention loop stopped")
			return
		case <-ticker.C:
			n, err := s.repo.PruneToLimit(ctx, perTokenLimit)
			if err != nil {
				s.logger.WarnContext(ctx, "retention loop: prune failed",
					"error", err, "per_token_limit", perTokenLimit)
				continue
			}
			if n > 0 {
				s.logger.InfoContext(ctx, "retention loop: pruned events",
					"deleted", n, "per_token_limit", perTokenLimit)
			}
		}
	}
}
