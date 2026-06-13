// ©AngelaMos | 2026
// generator.go

package kubeconfig

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
)

const (
	triggerPathPrefix = "/k/"

	contentTypeYAML = "application/yaml"
	defaultFilename = "kubeconfig"

	defaultClusterName = "prod-cluster"
	defaultUserName    = "svc-backup-reader"

	templateName = "kubeconfig"
)

//go:embed template.yaml.tmpl
var templateYAML string

var kubeconfigTemplate = template.Must(
	template.New(templateName).Parse(templateYAML),
)

type kubeconfigData struct {
	APIServerURL string
	Token        string
	ClusterName  string
	UserName     string
}

type Generator struct{}

func New() *Generator { return &Generator{} }

func (g *Generator) Type() token.Type { return token.TypeKubeconfig }

func (g *Generator) Generate(
	_ context.Context,
	t *token.Token,
	baseURL string,
) (generators.Artifact, error) {
	apiServerURL := strings.TrimRight(baseURL, "/") +
		triggerPathPrefix + t.ID
	data := kubeconfigData{
		APIServerURL: apiServerURL,
		Token:        t.ID,
		ClusterName:  defaultClusterName,
		UserName:     defaultUserName,
	}

	var buf bytes.Buffer
	if err := kubeconfigTemplate.Execute(&buf, data); err != nil {
		return generators.Artifact{}, fmt.Errorf(
			"kubeconfig: render template: %w",
			err,
		)
	}

	return generators.Artifact{
		Kind:        generators.KindText,
		Filename:    resolveFilename(t.Filename),
		Content:     buf.Bytes(),
		ContentType: contentTypeYAML,
	}, nil
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
