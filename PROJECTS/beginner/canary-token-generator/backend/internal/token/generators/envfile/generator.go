// ©AngelaMos | 2026
// generator.go

package envfile

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/middleware"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/envfile/recipes"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/pixel"
)

const (
	headerReferer      = "Referer"
	headerCacheControl = "Cache-Control"
	headerPragma       = "Pragma"

	cacheControlNoStore = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaNoCache       = "no-cache"

	triggerPathPrefix  = "/c/"
	metadataIncludeKey = "include_keys"

	contentType     = "text/plain; charset=utf-8"
	defaultFilename = ".env"

	canaryComment     = "Internal monitoring (Datadog-style integration)"
	canaryEndpointKey = "INTERNAL_METRICS_ENDPOINT"
	canaryTokenKey    = "INTERNAL_METRICS_TOKEN"
	canaryTokenPrefix = "tok_live_"
	canaryTokenLength = 32

	envfileHeader = "# Production environment\n" +
		"NODE_ENV=production\n" +
		"PORT=8080\n\n"
)

var defaultIncludeKeys = []string{"aws", "db"}

type Generator struct{}

func New() *Generator { return &Generator{} }

func (g *Generator) Type() token.Type { return token.TypeEnvfile }

func (g *Generator) Generate(
	_ context.Context,
	t *token.Token,
	baseURL string,
) (generators.Artifact, error) {
	keys := extractIncludeKeys(t.Metadata)
	triggerURL := strings.TrimRight(baseURL, "/") + triggerPathPrefix + t.ID

	sections := buildSections(keys, triggerURL)
	if err := shuffleSections(sections); err != nil {
		return generators.Artifact{}, fmt.Errorf(
			"envfile: shuffle sections: %w",
			err,
		)
	}

	body := renderSections(sections)

	return generators.Artifact{
		Kind:        generators.KindText,
		Filename:    resolveFilename(t.Filename),
		Content:     body,
		ContentType: contentType,
	}, nil
}

func (g *Generator) Trigger(
	_ context.Context,
	t *token.Token,
	r *http.Request,
) (*event.Event, *generators.TriggerResponse, error) {
	resp := &generators.TriggerResponse{
		StatusCode:  http.StatusOK,
		ContentType: pixel.ContentType,
		Body:        pixel.Clone(),
		ExtraHeaders: map[string]string{
			headerCacheControl: cacheControlNoStore,
			headerPragma:       pragmaNoCache,
		},
	}

	if t == nil {
		return nil, resp, nil
	}

	evt := &event.Event{
		TokenID:   t.ID,
		SourceIP:  middleware.RealIP(r),
		UserAgent: middleware.OptionalHeader(r.UserAgent()),
		Referer:   middleware.OptionalHeader(r.Header.Get(headerReferer)),
	}
	return evt, resp, nil
}

func buildSections(keys []string, triggerURL string) [][]recipes.EnvLine {
	sections := make([][]recipes.EnvLine, 0, len(keys)+1)
	for _, k := range keys {
		if r, ok := recipes.Get(k); ok {
			sections = append(sections, r.Generate())
		}
	}
	sections = append(sections, []recipes.EnvLine{
		{Comment: canaryComment},
		{Key: canaryEndpointKey, Value: triggerURL},
		{
			Key: canaryTokenKey,
			Value: canaryTokenPrefix +
				recipes.RandomAlnumMixed(canaryTokenLength),
		},
	})
	return sections
}

func shuffleSections(sections [][]recipes.EnvLine) error {
	for i := len(sections) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("crypto/rand.Int: %w", err)
		}
		j := int(jBig.Int64())
		sections[i], sections[j] = sections[j], sections[i]
	}
	return nil
}

func renderSections(sections [][]recipes.EnvLine) []byte {
	var buf bytes.Buffer
	buf.WriteString(envfileHeader)
	for _, s := range sections {
		for _, l := range s {
			if l.Comment != "" {
				fmt.Fprintf(&buf, "# %s\n", l.Comment)
			}
			if l.Key != "" {
				fmt.Fprintf(&buf, "%s=%s\n", l.Key, l.Value)
			}
		}
		buf.WriteString("\n")
	}
	return buf.Bytes()
}

func extractIncludeKeys(metadata json.RawMessage) []string {
	if len(metadata) == 0 {
		return cloneStrings(defaultIncludeKeys)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(metadata, &m); err != nil {
		return cloneStrings(defaultIncludeKeys)
	}
	raw, ok := m[metadataIncludeKey]
	if !ok {
		return cloneStrings(defaultIncludeKeys)
	}
	var keys []string
	if err := json.Unmarshal(raw, &keys); err != nil || len(keys) == 0 {
		return cloneStrings(defaultIncludeKeys)
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		out = append(out, k)
	}
	if len(out) == 0 {
		return cloneStrings(defaultIncludeKeys)
	}
	return out
}

func cloneStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func resolveFilename(name *string) string {
	if name == nil {
		return defaultFilename
	}
	trimmed := strings.TrimSpace(*name)
	if trimmed == "" {
		return defaultFilename
	}
	return trimmed
}
