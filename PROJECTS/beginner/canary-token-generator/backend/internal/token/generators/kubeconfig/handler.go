// ©AngelaMos | 2026
// handler.go

package kubeconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/middleware"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
)

const (
	headerReferer      = "Referer"
	headerUserAgent    = "User-Agent"
	headerCacheControl = "Cache-Control"
	headerPragma       = "Pragma"

	cacheControlNoStore = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaNoCache       = "no-cache"
	contentTypeJSON     = "application/json"

	statusKind       = "Status"
	statusAPIVersion = "v1"
	statusFailure    = "Failure"
	statusReason     = "Forbidden"
	statusMessageFmt = `%s is forbidden: User "system:anonymous" cannot %s resource "%s" in API group "" in the namespace "default"`

	defaultResource = "resource"

	verbList   = "list"
	verbCreate = "create"
	verbUpdate = "update"
	verbPatch  = "patch"
	verbDelete = "delete"

	extraKubectlPath   = "kubectl_path"
	extraKubectlMethod = "kubectl_method"
	extraKubectlQuery  = "kubectl_query"
	extraKubectlUA     = "kubectl_ua"
)

type kubernetesStatus struct {
	Kind       string         `json:"kind"`
	APIVersion string         `json:"apiVersion"`
	Metadata   statusMetadata `json:"metadata"`
	Status     string         `json:"status"`
	Message    string         `json:"message"`
	Reason     string         `json:"reason"`
	Code       int            `json:"code"`
}

type statusMetadata struct{}

func (g *Generator) Trigger(
	_ context.Context,
	t *token.Token,
	r *http.Request,
) (*event.Event, *generators.TriggerResponse, error) {
	resource := resourceFromPath(r.URL.Path)
	verb := verbFromMethod(r.Method)

	body, err := buildForbiddenBody(resource, verb)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"kubeconfig: build forbidden response: %w",
			err,
		)
	}

	resp := &generators.TriggerResponse{
		StatusCode:  http.StatusForbidden,
		ContentType: contentTypeJSON,
		Body:        body,
		ExtraHeaders: map[string]string{
			headerCacheControl: cacheControlNoStore,
			headerPragma:       pragmaNoCache,
		},
	}

	if t == nil {
		return nil, resp, nil
	}

	extra, err := buildKubectlExtra(r)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"kubeconfig: build event extra: %w",
			err,
		)
	}

	evt := &event.Event{
		TokenID:   t.ID,
		SourceIP:  middleware.RealIP(r),
		UserAgent: middleware.OptionalHeader(r.UserAgent()),
		Referer:   middleware.OptionalHeader(r.Header.Get(headerReferer)),
		Extra:     extra,
	}
	return evt, resp, nil
}

func buildForbiddenBody(resource, verb string) ([]byte, error) {
	s := kubernetesStatus{
		Kind:       statusKind,
		APIVersion: statusAPIVersion,
		Status:     statusFailure,
		Message:    fmt.Sprintf(statusMessageFmt, resource, verb, resource),
		Reason:     statusReason,
		Code:       http.StatusForbidden,
	}
	body, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshal kubernetes status: %w", err)
	}
	return body, nil
}

func buildKubectlExtra(r *http.Request) (json.RawMessage, error) {
	extra := map[string]string{
		extraKubectlPath:   r.URL.Path,
		extraKubectlMethod: r.Method,
		extraKubectlQuery:  r.URL.RawQuery,
		extraKubectlUA:     r.Header.Get(headerUserAgent),
	}
	body, err := json.Marshal(extra)
	if err != nil {
		return nil, fmt.Errorf("marshal kubectl extra: %w", err)
	}
	return body, nil
}

func resourceFromPath(urlPath string) string {
	last := path.Base(urlPath)
	if last == "" || last == "/" || last == "." {
		return defaultResource
	}
	return last
}

func verbFromMethod(method string) string {
	switch method {
	case http.MethodPost:
		return verbCreate
	case http.MethodPut:
		return verbUpdate
	case http.MethodPatch:
		return verbPatch
	case http.MethodDelete:
		return verbDelete
	default:
		return verbList
	}
}
