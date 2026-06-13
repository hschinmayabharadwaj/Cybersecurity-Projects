// ©AngelaMos | 2026
// service_test.go

package event_test

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/geoip"
)

const testTokenID = "tokevtsvc001"

type fakeStore struct {
	mu             sync.Mutex
	inserted       []*event.Event
	insertErr      error
	statusUpdates  []statusUpdate
	statusErr      error
	pruneCount     int64
	pruneErr       error
	pruneLastLimit int
}

type statusUpdate struct {
	id     int64
	status event.NotifyStatus
	sentAt *time.Time
}

func (f *fakeStore) Insert(_ context.Context, e *event.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.insertErr != nil {
		return f.insertErr
	}
	e.ID = int64(len(f.inserted) + 1)
	if e.TriggeredAt.IsZero() {
		e.TriggeredAt = time.Now().UTC()
	}
	if e.NotifyStatus == "" {
		e.NotifyStatus = event.NotifyPending
	}
	f.inserted = append(f.inserted, e)
	return nil
}

func (f *fakeStore) UpdateNotifyStatus(
	_ context.Context,
	id int64,
	status event.NotifyStatus,
	sentAt *time.Time,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statusErr != nil {
		return f.statusErr
	}
	f.statusUpdates = append(f.statusUpdates, statusUpdate{id, status, sentAt})
	return nil
}

func (f *fakeStore) PruneToLimit(
	_ context.Context,
	perTokenLimit int,
) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pruneLastLimit = perTokenLimit
	if f.pruneErr != nil {
		return 0, f.pruneErr
	}
	return f.pruneCount, nil
}

func (f *fakeStore) snapshot() ([]*event.Event, []statusUpdate) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ev := make([]*event.Event, len(f.inserted))
	copy(ev, f.inserted)
	su := make([]statusUpdate, len(f.statusUpdates))
	copy(su, f.statusUpdates)
	return ev, su
}

type fakeIncrementer struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (f *fakeIncrementer) IncrementTriggerCount(
	_ context.Context,
	id string,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, id)
	return f.err
}

func (f *fakeIncrementer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type fakeLookuper struct {
	mu     sync.Mutex
	called []string
	result geoip.Lookup
}

func (f *fakeLookuper) Lookup(ip string) geoip.Lookup {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called = append(f.called, ip)
	return f.result
}

func (f *fakeLookuper) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.called))
	copy(out, f.called)
	return out
}

type fakeNotifier struct {
	mu    sync.Mutex
	calls []notifyCall
}

type notifyCall struct {
	info event.NotifyInfo
	evt  *event.Event
}

func (f *fakeNotifier) Notify(info event.NotifyInfo, evt *event.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, notifyCall{info, evt})
}

func (f *fakeNotifier) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func setupRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		if cErr := rdb.Close(); cErr != nil {
			t.Logf("redis close: %v", cErr)
		}
	})
	return rdb, mr
}

func sampleInfo() event.NotifyInfo {
	return event.NotifyInfo{
		TokenID:      testTokenID,
		ManageID:     "abcd-1234",
		Type:         "webbug",
		Memo:         "test",
		AlertChannel: "telegram",
		TelegramBot:  "bot",
		TelegramChat: "chat",
	}
}

func sampleEvent(ip string) *event.Event {
	return &event.Event{TokenID: testTokenID, SourceIP: ip}
}

func newSvc(
	t *testing.T,
	store event.Store,
	tokens event.TokenIncrementer,
	rdb *redis.Client,
	notifier event.Notifier,
) *event.Service {
	t.Helper()
	return event.NewService(store, tokens, rdb, notifier, event.ServiceConfig{
		DedupTTL: 15 * time.Minute,
		Logger:   slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	})
}

func newSvcWithGeo(
	t *testing.T,
	store event.Store,
	tokens event.TokenIncrementer,
	rdb *redis.Client,
	geo geoip.Lookuper,
) *event.Service {
	t.Helper()
	return event.NewService(store, tokens, rdb, nil, event.ServiceConfig{
		DedupTTL: 15 * time.Minute,
		Logger:   slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		GeoIP:    geo,
	})
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(
	p []byte,
) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

func TestService_Record_InsertsEvent(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	inc := &fakeIncrementer{}
	rdb, _ := setupRedis(t)
	notifier := &fakeNotifier{}
	svc := newSvc(t, store, inc, rdb, notifier)

	evt := sampleEvent("203.0.113.1")
	require.NoError(t, svc.Record(context.Background(), sampleInfo(), evt))

	inserted, _ := store.snapshot()
	require.Len(t, inserted, 1)
	require.Equal(t, "203.0.113.1", inserted[0].SourceIP)
	require.NotZero(t, evt.ID, "Insert assigns ID")
}

func TestService_Record_IncrementsTriggerCount(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	inc := &fakeIncrementer{}
	rdb, _ := setupRedis(t)
	svc := newSvc(t, store, inc, rdb, nil)

	require.NoError(
		t,
		svc.Record(
			context.Background(),
			sampleInfo(),
			sampleEvent("203.0.113.1"),
		),
	)
	require.Equal(t, 1, inc.callCount())
}

func TestService_Record_FirstTriggerNotifies(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	inc := &fakeIncrementer{}
	rdb, _ := setupRedis(t)
	notifier := &fakeNotifier{}
	svc := newSvc(t, store, inc, rdb, notifier)

	require.NoError(
		t,
		svc.Record(
			context.Background(),
			sampleInfo(),
			sampleEvent("203.0.113.1"),
		),
	)
	require.Equal(t, 1, notifier.callCount())

	_, statusUpdates := store.snapshot()
	require.Empty(
		t,
		statusUpdates,
		"first trigger should not write 'deduped' status; notify.Service handles sent/failed writeback async",
	)
}

func TestService_Record_DuplicateMarksDeduped(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	inc := &fakeIncrementer{}
	rdb, mr := setupRedis(t)
	notifier := &fakeNotifier{}
	svc := newSvc(t, store, inc, rdb, notifier)

	require.NoError(
		t,
		svc.Record(
			context.Background(),
			sampleInfo(),
			sampleEvent("203.0.113.1"),
		),
	)
	require.NoError(
		t,
		svc.Record(
			context.Background(),
			sampleInfo(),
			sampleEvent("203.0.113.1"),
		),
	)

	require.Equal(t, 1, notifier.callCount(), "duplicate must not notify")

	inserted, statusUpdates := store.snapshot()
	require.Len(t, inserted, 2, "both events still recorded")
	require.Len(t, statusUpdates, 1, "duplicate writes deduped status")
	require.Equal(t, event.NotifyDeduped, statusUpdates[0].status)
	require.Equal(t, inserted[1].ID, statusUpdates[0].id)

	dedupKey := "dedup:trigger:" + testTokenID + ":203.0.113.1"
	val, err := mr.Get(dedupKey)
	require.NoError(t, err)
	require.Equal(t, "2", val, "INCR bumps counter")
}

func TestService_Record_DifferentIPsBothNotify(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	inc := &fakeIncrementer{}
	rdb, _ := setupRedis(t)
	notifier := &fakeNotifier{}
	svc := newSvc(t, store, inc, rdb, notifier)

	require.NoError(
		t,
		svc.Record(
			context.Background(),
			sampleInfo(),
			sampleEvent("203.0.113.1"),
		),
	)
	require.NoError(
		t,
		svc.Record(
			context.Background(),
			sampleInfo(),
			sampleEvent("203.0.113.2"),
		),
	)

	require.Equal(t, 2, notifier.callCount(), "different IPs each notify")
}

func TestService_Record_DedupTTLExpiry(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	inc := &fakeIncrementer{}
	rdb, mr := setupRedis(t)
	notifier := &fakeNotifier{}
	svc := event.NewService(store, inc, rdb, notifier, event.ServiceConfig{
		DedupTTL: 1 * time.Second,
		Logger:   slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	})

	require.NoError(
		t,
		svc.Record(
			context.Background(),
			sampleInfo(),
			sampleEvent("203.0.113.1"),
		),
	)
	mr.FastForward(2 * time.Second)
	require.NoError(
		t,
		svc.Record(
			context.Background(),
			sampleInfo(),
			sampleEvent("203.0.113.1"),
		),
	)

	require.Equal(
		t,
		2,
		notifier.callCount(),
		"after TTL expiry second trigger notifies again",
	)
}

func TestService_Record_DedupKeyShape(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	inc := &fakeIncrementer{}
	rdb, mr := setupRedis(t)
	svc := newSvc(t, store, inc, rdb, nil)

	require.NoError(
		t,
		svc.Record(
			context.Background(),
			sampleInfo(),
			sampleEvent("203.0.113.99"),
		),
	)

	keys := mr.Keys()
	require.Contains(t, keys, "dedup:trigger:"+testTokenID+":203.0.113.99")
}

func TestService_Record_RedisDownFailsOpen(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	inc := &fakeIncrementer{}
	rdb, mr := setupRedis(t)
	notifier := &fakeNotifier{}
	svc := newSvc(t, store, inc, rdb, notifier)

	mr.Close()
	require.NoError(
		t,
		svc.Record(
			context.Background(),
			sampleInfo(),
			sampleEvent("203.0.113.1"),
		),
	)
	require.Equal(t, 1, notifier.callCount(),
		"redis down → fail open → still notify so we don't miss alerts")
}

func TestService_Record_InsertErrorReturns(t *testing.T) {
	t.Parallel()
	store := &fakeStore{insertErr: errors.New("db down")}
	inc := &fakeIncrementer{}
	rdb, _ := setupRedis(t)
	notifier := &fakeNotifier{}
	svc := newSvc(t, store, inc, rdb, notifier)

	err := svc.Record(
		context.Background(),
		sampleInfo(),
		sampleEvent("203.0.113.1"),
	)
	require.Error(t, err)
	require.Equal(
		t,
		0,
		notifier.callCount(),
		"insert failure prevents notify — we don't have an event id to write back to",
	)
}

func TestService_Record_IncrementErrorDoesNotPropagate(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	inc := &fakeIncrementer{err: errors.New("update failed")}
	rdb, _ := setupRedis(t)
	notifier := &fakeNotifier{}
	svc := newSvc(t, store, inc, rdb, notifier)

	require.NoError(
		t,
		svc.Record(
			context.Background(),
			sampleInfo(),
			sampleEvent("203.0.113.1"),
		),
		"increment failure is best-effort; record should still succeed",
	)
	require.Equal(t, 1, notifier.callCount())
}

func TestService_Record_NilNotifierNoCrash(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	inc := &fakeIncrementer{}
	rdb, _ := setupRedis(t)
	svc := newSvc(t, store, inc, rdb, nil)

	require.NotPanics(t, func() {
		if err := svc.Record(
			context.Background(),
			sampleInfo(),
			sampleEvent("203.0.113.1"),
		); err != nil {
			t.Logf("record: %v", err)
		}
	})
}

func TestService_Record_ConcurrentSafe(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	inc := &fakeIncrementer{}
	rdb, _ := setupRedis(t)
	notifier := &fakeNotifier{}
	svc := newSvc(t, store, inc, rdb, notifier)

	const n = 20
	var wg sync.WaitGroup
	var notified atomic.Int32
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := "203.0.113." + strconv.Itoa(i+1)
			if err := svc.Record(
				context.Background(),
				sampleInfo(),
				sampleEvent(ip),
			); err == nil {
				notified.Add(1)
			}
		}(i)
	}
	wg.Wait()
	require.Equal(t, int32(n), notified.Load())
	require.Equal(t, n, notifier.callCount())
}

func TestService_CountActiveDedup_NoKeysReturnsZero(t *testing.T) {
	t.Parallel()
	rdb, _ := setupRedis(t)
	svc := newSvc(t, &fakeStore{}, &fakeIncrementer{}, rdb, nil)

	n, err := svc.CountActiveDedup(context.Background(), testTokenID)
	require.NoError(t, err)
	require.Equal(t, int64(0), n)
}

func TestService_CountActiveDedup_FirstTriggerOnlyCountsZero(t *testing.T) {
	t.Parallel()
	rdb, _ := setupRedis(t)
	svc := newSvc(t, &fakeStore{}, &fakeIncrementer{}, rdb, nil)

	require.NoError(
		t,
		svc.Record(
			context.Background(),
			sampleInfo(),
			sampleEvent("203.0.113.1"),
		),
	)

	n, err := svc.CountActiveDedup(context.Background(), testTokenID)
	require.NoError(t, err)
	require.Equal(t, int64(0), n,
		"first trigger fires the notification; nothing silenced yet")
}

func TestService_CountActiveDedup_CountsSilencedAcrossIPs(t *testing.T) {
	t.Parallel()
	rdb, _ := setupRedis(t)
	svc := newSvc(t, &fakeStore{}, &fakeIncrementer{}, rdb, nil)

	for range 3 {
		require.NoError(
			t,
			svc.Record(
				context.Background(),
				sampleInfo(),
				sampleEvent("203.0.113.1"),
			),
		)
	}
	for range 5 {
		require.NoError(
			t,
			svc.Record(
				context.Background(),
				sampleInfo(),
				sampleEvent("203.0.113.2"),
			),
		)
	}

	n, err := svc.CountActiveDedup(context.Background(), testTokenID)
	require.NoError(t, err)
	require.Equal(t, int64(2), n,
		"two distinct IPs were silenced (203.0.113.1 and 203.0.113.2)")
}

func TestService_CountActiveDedup_IgnoresOtherTokens(t *testing.T) {
	t.Parallel()
	rdb, _ := setupRedis(t)
	svc := newSvc(t, &fakeStore{}, &fakeIncrementer{}, rdb, nil)

	for range 3 {
		require.NoError(
			t,
			svc.Record(
				context.Background(),
				sampleInfo(),
				sampleEvent("203.0.113.1"),
			),
		)
	}
	otherInfo := sampleInfo()
	otherInfo.TokenID = "tokother0001"
	for range 4 {
		require.NoError(
			t,
			svc.Record(
				context.Background(),
				otherInfo,
				&event.Event{TokenID: "tokother0001", SourceIP: "203.0.113.5"},
			),
		)
	}

	n, err := svc.CountActiveDedup(context.Background(), testTokenID)
	require.NoError(t, err)
	require.Equal(t, int64(1), n,
		"only this token's silenced IPs counted (one distinct IP)")
}

func TestService_CountActiveDedup_NilRedisReturnsZero(t *testing.T) {
	t.Parallel()
	svc := event.NewService(
		&fakeStore{},
		&fakeIncrementer{},
		nil,
		nil,
		event.ServiceConfig{
			DedupTTL: 15 * time.Minute,
			Logger:   slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		},
	)
	n, err := svc.CountActiveDedup(context.Background(), testTokenID)
	require.NoError(t, err)
	require.Equal(t, int64(0), n)
}

func TestService_RunRetentionLoop_PrunesAtInterval(t *testing.T) {
	t.Parallel()
	store := &fakeStore{pruneCount: 5}
	rdb, _ := setupRedis(t)
	svc := newSvc(t, store, &fakeIncrementer{}, rdb, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		svc.RunRetentionLoop(ctx, 25*time.Millisecond, 100)
		close(done)
	}()

	require.Eventually(t, func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		return store.pruneLastLimit == 100
	}, 1*time.Second, 5*time.Millisecond)

	cancel()
	<-done
}

func TestService_RunRetentionLoop_StopsOnContextCancel(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	rdb, _ := setupRedis(t)
	svc := newSvc(t, store, &fakeIncrementer{}, rdb, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		svc.RunRetentionLoop(ctx, 10*time.Millisecond, 50)
		close(done)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("retention loop did not stop on cancel")
	}
}

func TestService_RunRetentionLoop_ContinuesOnPruneError(t *testing.T) {
	t.Parallel()
	store := &fakeStore{pruneErr: errors.New("db down")}
	rdb, _ := setupRedis(t)
	svc := newSvc(t, store, &fakeIncrementer{}, rdb, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		svc.RunRetentionLoop(ctx, 10*time.Millisecond, 50)
		close(done)
	}()

	time.Sleep(60 * time.Millisecond)
	cancel()
	<-done
}

func TestService_RunRetentionLoop_DisabledOnInvalidConfig(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	rdb, _ := setupRedis(t)
	svc := newSvc(t, store, &fakeIncrementer{}, rdb, nil)

	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		svc.RunRetentionLoop(ctx, 0, 100)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal(
			"retention loop should have returned immediately on invalid interval",
		)
	}

	require.Equal(t, 0, store.pruneLastLimit)
}

func TestService_Record_EnrichesGeoBeforeInsert(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	inc := &fakeIncrementer{}
	rdb, _ := setupRedis(t)
	geo := &fakeLookuper{result: geoip.Lookup{
		Country: "US", Region: "California", City: "Mountain View",
		ASN: 15169, ASNOrg: "Google LLC",
	}}
	svc := newSvcWithGeo(t, store, inc, rdb, geo)

	evt := sampleEvent("203.0.113.1")
	require.NoError(t, svc.Record(context.Background(), sampleInfo(), evt))

	require.Equal(t, []string{"203.0.113.1"}, geo.calls(),
		"Record must invoke Lookup exactly once with the event's source IP")

	inserted, _ := store.snapshot()
	require.Len(t, inserted, 1)
	got := inserted[0]
	require.NotNil(t, got.GeoCountry)
	require.Equal(t, "US", *got.GeoCountry)
	require.NotNil(t, got.GeoCity)
	require.Equal(t, "Mountain View", *got.GeoCity)
	require.NotNil(t, got.GeoASN)
	require.Equal(t, 15169, *got.GeoASN)
}

func TestService_Record_NoGeoConfigured_LeavesGeoNil(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	inc := &fakeIncrementer{}
	rdb, _ := setupRedis(t)
	svc := newSvc(t, store, inc, rdb, nil)

	evt := sampleEvent("203.0.113.1")
	require.NoError(t, svc.Record(context.Background(), sampleInfo(), evt))

	inserted, _ := store.snapshot()
	require.Len(t, inserted, 1)
	require.Nil(t, inserted[0].GeoCountry)
	require.Nil(t, inserted[0].GeoCity)
	require.Nil(t, inserted[0].GeoASN)
}

func TestService_Record_EmptySourceIP_SkipsLookup(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	inc := &fakeIncrementer{}
	rdb, _ := setupRedis(t)
	geo := &fakeLookuper{result: geoip.Lookup{Country: "ZZ"}}
	svc := newSvcWithGeo(t, store, inc, rdb, geo)

	evt := &event.Event{TokenID: testTokenID}
	require.NoError(t, svc.Record(context.Background(), sampleInfo(), evt))

	require.Empty(t, geo.calls(),
		"empty source IP must short-circuit the geo lookup "+
			"(no useful enrichment possible)")
	inserted, _ := store.snapshot()
	require.Nil(t, inserted[0].GeoCountry)
}

func TestService_Record_NopLookuper_LeavesGeoNil(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	inc := &fakeIncrementer{}
	rdb, _ := setupRedis(t)
	svc := newSvcWithGeo(t, store, inc, rdb, geoip.NopService())

	evt := sampleEvent("203.0.113.1")
	require.NoError(t, svc.Record(context.Background(), sampleInfo(), evt))

	inserted, _ := store.snapshot()
	require.Nil(t, inserted[0].GeoCountry,
		"NopService returns empty Lookup; AttachGeoIP leaves all fields nil")
}

func TestService_Record_GeoEnrichmentBestEffort_InsertErrorBubbles(
	t *testing.T,
) {
	t.Parallel()
	store := &fakeStore{insertErr: errors.New("db down")}
	inc := &fakeIncrementer{}
	rdb, _ := setupRedis(t)
	geo := &fakeLookuper{result: geoip.Lookup{Country: "US"}}
	svc := newSvcWithGeo(t, store, inc, rdb, geo)

	err := svc.Record(context.Background(), sampleInfo(),
		sampleEvent("203.0.113.1"))
	require.Error(t, err, "insert error path is unchanged by geo enrichment")
	require.Equal(t, []string{"203.0.113.1"}, geo.calls(),
		"enrichment runs even when insert later fails "+
			"(no upstream side-effect)")
}
