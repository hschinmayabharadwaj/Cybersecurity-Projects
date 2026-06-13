// ©AngelaMos | 2026
// generator.go

package docx

import (
	"archive/zip"
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/middleware"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/pixel"
)

const (
	headerReferer      = "Referer"
	headerCacheControl = "Cache-Control"
	headerPragma       = "Pragma"

	cacheControlNoStore = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaNoCache       = "no-cache"

	triggerPathPrefix = "/c/"

	placeholder = "HONEY_TRACK_URL"
	footerEntry = "word/footer2.xml"

	contentType     = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	defaultFilename = "Document.docx"
)

//go:embed template/template.docx
var docxTemplate []byte

type Generator struct{}

func New() *Generator { return &Generator{} }

func (g *Generator) Type() token.Type { return token.TypeDocx }

func (g *Generator) Generate(
	_ context.Context,
	t *token.Token,
	baseURL string,
) (generators.Artifact, error) {
	triggerURL := strings.TrimRight(baseURL, "/") + triggerPathPrefix + t.ID

	patched, err := patchTemplate(docxTemplate, triggerURL)
	if err != nil {
		return generators.Artifact{}, err
	}

	return generators.Artifact{
		Kind:        generators.KindFile,
		Filename:    resolveFilename(t.Filename),
		Content:     patched,
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

func patchTemplate(template []byte, triggerURL string) ([]byte, error) {
	in, err := zip.NewReader(bytes.NewReader(template), int64(len(template)))
	if err != nil {
		return nil, fmt.Errorf("docx: parse template: %w", err)
	}

	var out bytes.Buffer
	w := zip.NewWriter(&out)
	for _, f := range in.File {
		rc, oErr := f.Open()
		if oErr != nil {
			return nil, fmt.Errorf("docx: open %s: %w", f.Name, oErr)
		}
		body, rErr := io.ReadAll(rc)
		cErr := rc.Close()
		if rErr != nil {
			return nil, fmt.Errorf("docx: read %s: %w", f.Name, rErr)
		}
		if cErr != nil {
			return nil, fmt.Errorf("docx: close %s: %w", f.Name, cErr)
		}

		if f.Name == footerEntry {
			body = bytes.Replace(
				body,
				[]byte(placeholder),
				[]byte(triggerURL),
				1,
			)
		}

		hdr := &zip.FileHeader{Name: f.Name, Method: f.Method}
		fw, hErr := w.CreateHeader(hdr)
		if hErr != nil {
			return nil, fmt.Errorf("docx: create %s: %w", f.Name, hErr)
		}
		if _, wErr := fw.Write(body); wErr != nil {
			return nil, fmt.Errorf("docx: write %s: %w", f.Name, wErr)
		}
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("docx: close zip writer: %w", err)
	}
	return out.Bytes(), nil
}
