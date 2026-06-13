// ©AngelaMos | 2026
// service_test.go

package token_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
)

type fakeRepo struct {
	mu        sync.Mutex
	inserted  []*token.Token
	byID      map[string]*token.Token
	byManage  map[string]*token.Token
	insertErr error
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		byID:     map[string]*token.Token{},
		byManage: map[string]*token.Token{},
	}
}

func (f *fakeRepo) Insert(_ context.Context, t *token.Token) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.insertErr != nil {
		return f.insertErr
	}
	f.inserted = append(f.inserted, t)
	f.byID[t.ID] = t
	f.byManage[t.ManageID] = t
	return nil
}

func (f *fakeRepo) GetByID(_ context.Context, id string) (*token.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.byID[id]
	if !ok {
		return nil, token.ErrNotFound
	}
	return t, nil
}

func (f *fakeRepo) GetByManageID(
	_ context.Context,
	manageID string,
) (*token.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.byManage[manageID]
	if !ok {
		return nil, token.ErrNotFound
	}
	return t, nil
}

func (f *fakeRepo) IncrementTriggerCount(_ context.Context, _ string) error {
	return nil
}

func (f *fakeRepo) DeleteByManageID(
	_ context.Context,
	manageID string,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.byManage[manageID]
	if !ok {
		return token.ErrNotFound
	}
	delete(f.byManage, manageID)
	delete(f.byID, t.ID)
	return nil
}

type fakeGenerator struct {
	tokenType   token.Type
	artifact    generators.Artifact
	generateErr error
	calls       atomic.Int32
}

func (g *fakeGenerator) Type() token.Type { return g.tokenType }

func (g *fakeGenerator) Generate(
	_ context.Context,
	_ *token.Token,
	_ string,
) (generators.Artifact, error) {
	g.calls.Add(1)
	if g.generateErr != nil {
		return generators.Artifact{}, g.generateErr
	}
	return g.artifact, nil
}

func (g *fakeGenerator) Trigger(
	_ context.Context,
	_ *token.Token,
	_ *http.Request,
) (*event.Event, *generators.TriggerResponse, error) {
	return nil, nil, nil
}

func newWebbugReq() token.CreateRequest {
	return token.CreateRequest{
		Type:          token.TypeWebbug,
		Memo:          "test",
		AlertChannel:  token.ChannelWebhook,
		WebhookURL:    "https://example.com/hook",
		TurnstileResp: "stub-token",
	}
}

func TestService_Create_GeneratesValidIDAndManageID(t *testing.T) {
	repo := newFakeRepo()
	gen := &fakeGenerator{
		tokenType: token.TypeWebbug,
		artifact:  generators.Artifact{Kind: generators.KindURL, URL: "x"},
	}
	svc := token.NewService(
		repo,
		token.MapRegistry{token.TypeWebbug: gen},
		token.ServiceConfig{
			BaseURL:   "https://canary.example.com",
			ManageURL: "https://canary.example.com",
		},
	)

	tok, _, err := svc.Create(
		context.Background(),
		newWebbugReq(),
		"fp",
		"1.2.3.4",
	)
	require.NoError(t, err)
	require.NotNil(t, tok)

	require.Regexp(t, `^[a-z0-9]{12}$`, tok.ID)
	require.Regexp(
		t,
		`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
		tok.ManageID,
	)
}

func TestService_Create_PersistsToRepo(t *testing.T) {
	repo := newFakeRepo()
	gen := &fakeGenerator{
		tokenType: token.TypeWebbug,
		artifact:  generators.Artifact{Kind: generators.KindURL},
	}
	svc := token.NewService(repo, token.MapRegistry{token.TypeWebbug: gen},
		token.ServiceConfig{BaseURL: "https://canary.example.com"})

	tok, _, err := svc.Create(
		context.Background(),
		newWebbugReq(),
		"fp",
		"1.2.3.4",
	)
	require.NoError(t, err)
	require.Len(t, repo.inserted, 1)
	require.Equal(t, tok.ID, repo.inserted[0].ID)
	require.Equal(t, "1.2.3.4", repo.inserted[0].CreatedIP)
	require.Equal(t, "fp", repo.inserted[0].CreatedFP)
	require.True(t, repo.inserted[0].Enabled)
}

func TestService_Create_CallsGeneratorWithBaseURL(t *testing.T) {
	repo := newFakeRepo()
	gen := &fakeGenerator{
		tokenType: token.TypeWebbug,
		artifact:  generators.Artifact{Kind: generators.KindURL, URL: "x"},
	}
	svc := token.NewService(repo, token.MapRegistry{token.TypeWebbug: gen},
		token.ServiceConfig{BaseURL: "https://canary.example.com"})

	_, _, err := svc.Create(
		context.Background(),
		newWebbugReq(),
		"fp",
		"1.2.3.4",
	)
	require.NoError(t, err)
	require.Equal(t, int32(1), gen.calls.Load())
}

func TestService_Create_UnknownTypeReturnsError(t *testing.T) {
	repo := newFakeRepo()
	svc := token.NewService(repo, token.MapRegistry{},
		token.ServiceConfig{BaseURL: "https://canary.example.com"})

	_, _, err := svc.Create(
		context.Background(),
		newWebbugReq(),
		"fp",
		"1.2.3.4",
	)
	require.Error(t, err)
	require.ErrorIs(t, err, token.ErrUnknownGeneratorType)
}

func TestService_Create_ValidationFails(t *testing.T) {
	repo := newFakeRepo()
	gen := &fakeGenerator{tokenType: token.TypeWebbug}
	svc := token.NewService(repo, token.MapRegistry{token.TypeWebbug: gen},
		token.ServiceConfig{BaseURL: "https://canary.example.com"})

	req := newWebbugReq()
	req.AlertChannel = ""
	_, _, err := svc.Create(context.Background(), req, "fp", "1.2.3.4")
	require.Error(t, err)
}

func TestService_Create_SlowredirectMissingDestinationFails(t *testing.T) {
	repo := newFakeRepo()
	gen := &fakeGenerator{tokenType: token.TypeSlowRedirect}
	svc := token.NewService(
		repo,
		token.MapRegistry{token.TypeSlowRedirect: gen},
		token.ServiceConfig{BaseURL: "https://canary.example.com"},
	)

	req := newWebbugReq()
	req.Type = token.TypeSlowRedirect
	_, _, err := svc.Create(context.Background(), req, "fp", "1.2.3.4")
	require.Error(t, err)
	require.ErrorIs(t, err, token.ErrInvalidDestinationURL)
}

func TestService_Create_SlowredirectInvalidSchemeFails(t *testing.T) {
	repo := newFakeRepo()
	gen := &fakeGenerator{tokenType: token.TypeSlowRedirect}
	svc := token.NewService(
		repo,
		token.MapRegistry{token.TypeSlowRedirect: gen},
		token.ServiceConfig{BaseURL: "https://canary.example.com"},
	)

	req := newWebbugReq()
	req.Type = token.TypeSlowRedirect
	req.Metadata = json.RawMessage(`{"destination_url":"javascript:alert(1)"}`)
	_, _, err := svc.Create(context.Background(), req, "fp", "1.2.3.4")
	require.ErrorIs(t, err, token.ErrInvalidDestinationURL)
}

func TestService_Create_SlowredirectValidURLSucceeds(t *testing.T) {
	repo := newFakeRepo()
	gen := &fakeGenerator{
		tokenType: token.TypeSlowRedirect,
		artifact:  generators.Artifact{Kind: generators.KindURL},
	}
	svc := token.NewService(
		repo,
		token.MapRegistry{token.TypeSlowRedirect: gen},
		token.ServiceConfig{BaseURL: "https://canary.example.com"},
	)

	req := newWebbugReq()
	req.Type = token.TypeSlowRedirect
	req.Metadata = json.RawMessage(`{"destination_url":"https://example.com"}`)
	_, _, err := svc.Create(context.Background(), req, "fp", "1.2.3.4")
	require.NoError(t, err)
}

func TestService_Create_EnvfileInvalidKeyFails(t *testing.T) {
	repo := newFakeRepo()
	gen := &fakeGenerator{
		tokenType: token.TypeEnvfile,
		artifact:  generators.Artifact{Kind: generators.KindText},
	}
	svc := token.NewService(repo, token.MapRegistry{token.TypeEnvfile: gen},
		token.ServiceConfig{BaseURL: "https://canary.example.com"})

	req := newWebbugReq()
	req.Type = token.TypeEnvfile
	req.Metadata = json.RawMessage(`{"include_keys":["aws","nonexistent"]}`)
	_, _, err := svc.Create(context.Background(), req, "fp", "1.2.3.4")
	require.ErrorIs(t, err, token.ErrInvalidIncludeKeys)
}

func TestService_Create_EnvfileValidKeysSucceeds(t *testing.T) {
	repo := newFakeRepo()
	gen := &fakeGenerator{
		tokenType: token.TypeEnvfile,
		artifact:  generators.Artifact{Kind: generators.KindText},
	}
	svc := token.NewService(repo, token.MapRegistry{token.TypeEnvfile: gen},
		token.ServiceConfig{BaseURL: "https://canary.example.com"})

	req := newWebbugReq()
	req.Type = token.TypeEnvfile
	req.Metadata = json.RawMessage(`{"include_keys":["aws","stripe"]}`)
	_, _, err := svc.Create(context.Background(), req, "fp", "1.2.3.4")
	require.NoError(t, err)
}

func TestService_Create_GeneratorErrorPropagates(t *testing.T) {
	repo := newFakeRepo()
	gen := &fakeGenerator{
		tokenType:   token.TypeWebbug,
		generateErr: errors.New("generate failed"),
	}
	svc := token.NewService(repo, token.MapRegistry{token.TypeWebbug: gen},
		token.ServiceConfig{BaseURL: "https://canary.example.com"})

	_, _, err := svc.Create(
		context.Background(),
		newWebbugReq(),
		"fp",
		"1.2.3.4",
	)
	require.ErrorIs(t, err, token.ErrGenerateFailed)
	require.Empty(t, repo.inserted, "must not persist if generator failed")
}

func TestService_Create_DistinctIDsAcrossCalls(t *testing.T) {
	repo := newFakeRepo()
	gen := &fakeGenerator{
		tokenType: token.TypeWebbug,
		artifact:  generators.Artifact{Kind: generators.KindURL},
	}
	svc := token.NewService(repo, token.MapRegistry{token.TypeWebbug: gen},
		token.ServiceConfig{BaseURL: "https://canary.example.com"})

	seen := make(map[string]struct{})
	for range 30 {
		tok, _, err := svc.Create(
			context.Background(),
			newWebbugReq(),
			"fp",
			"1.2.3.4",
		)
		require.NoError(t, err)
		seen[tok.ID] = struct{}{}
	}
	require.Greater(
		t,
		len(seen),
		28,
		"ID generation must be sufficiently random",
	)
}

type collisionRepo struct {
	mu         sync.Mutex
	collisions int
	remaining  int
	inserted   []*token.Token
	byID       map[string]*token.Token
}

func newCollisionRepo(collisions int) *collisionRepo {
	return &collisionRepo{
		remaining: collisions,
		byID:      map[string]*token.Token{},
	}
}

func (r *collisionRepo) Insert(_ context.Context, t *token.Token) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.remaining > 0 {
		r.remaining--
		r.collisions++
		return &pgconn.PgError{Code: "23505"}
	}
	r.inserted = append(r.inserted, t)
	r.byID[t.ID] = t
	return nil
}

func (r *collisionRepo) GetByID(
	_ context.Context, id string,
) (*token.Token, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.byID[id]
	if !ok {
		return nil, token.ErrNotFound
	}
	return t, nil
}

func (r *collisionRepo) GetByManageID(
	_ context.Context, _ string,
) (*token.Token, error) {
	return nil, token.ErrNotFound
}

func (r *collisionRepo) IncrementTriggerCount(
	_ context.Context, _ string,
) error {
	return nil
}

func (r *collisionRepo) DeleteByManageID(
	_ context.Context, _ string,
) error {
	return token.ErrNotFound
}

func TestService_Create_RetriesOnTokenIDCollision(t *testing.T) {
	repo := newCollisionRepo(2)
	gen := &fakeGenerator{
		tokenType: token.TypeWebbug,
		artifact: generators.Artifact{
			Kind: generators.KindURL,
			URL:  "https://canary.example.com/c/x",
		},
	}
	svc := token.NewService(
		repo,
		token.MapRegistry{token.TypeWebbug: gen},
		token.ServiceConfig{BaseURL: "https://canary.example.com"},
	)

	tok, _, err := svc.Create(context.Background(), token.CreateRequest{
		Type:         token.TypeWebbug,
		Memo:         "x",
		AlertChannel: token.ChannelWebhook,
		WebhookURL:   "https://example.com/h",
	}, "fp", "ip")
	require.NoError(t, err)
	require.NotNil(t, tok)
	require.Equal(t, 2, repo.collisions,
		"repo must have rejected exactly two prior IDs")
	require.Len(t, repo.inserted, 1, "exactly one token persisted")
	require.Equal(t, int32(3), gen.calls.Load(),
		"generator called once per attempt (regenerates artifact per id)")
}

func TestService_Create_GivesUpAfterMaxCollisions(t *testing.T) {
	repo := newCollisionRepo(10)
	gen := &fakeGenerator{
		tokenType: token.TypeWebbug,
		artifact: generators.Artifact{
			Kind: generators.KindURL,
			URL:  "https://canary.example.com/c/x",
		},
	}
	svc := token.NewService(
		repo,
		token.MapRegistry{token.TypeWebbug: gen},
		token.ServiceConfig{BaseURL: "https://canary.example.com"},
	)

	_, _, err := svc.Create(context.Background(), token.CreateRequest{
		Type:         token.TypeWebbug,
		Memo:         "x",
		AlertChannel: token.ChannelWebhook,
		WebhookURL:   "https://example.com/h",
	}, "fp", "ip")
	require.Error(t, err)
	require.Contains(t, err.Error(), "id-collision retries")
}

func TestService_GetByID_NotFoundReturnsNilNil(t *testing.T) {
	repo := newFakeRepo()
	svc := token.NewService(repo, token.MapRegistry{},
		token.ServiceConfig{BaseURL: "https://canary.example.com"})

	tok, err := svc.GetByID(context.Background(), "nope")
	require.NoError(t, err)
	require.Nil(t, tok)
}

func TestService_TriggerURL(t *testing.T) {
	svc := token.NewService(newFakeRepo(), token.MapRegistry{},
		token.ServiceConfig{BaseURL: "https://canary.example.com/"})
	require.Equal(t, "https://canary.example.com/c/abc", svc.TriggerURL("abc"))
}

func TestService_ManageURL(t *testing.T) {
	svc := token.NewService(newFakeRepo(), token.MapRegistry{},
		token.ServiceConfig{ManageURL: "https://canary.example.com/"})
	require.Equal(t, "https://canary.example.com/m/uuid", svc.ManageURL("uuid"))
}
