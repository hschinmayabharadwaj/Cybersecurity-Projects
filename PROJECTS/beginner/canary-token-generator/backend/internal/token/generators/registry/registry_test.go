// ©AngelaMos | 2026
// registry_test.go

package registry_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/registry"
)

const testBaseURL = "https://canary.example.com"

func TestBuild_RegistersWebbug(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg[token.TypeWebbug]
	require.True(t, ok, "expected webbug generator registered")
	require.NotNil(t, g)
	require.Equal(t, token.TypeWebbug, g.Type())
}

func TestBuild_RegistersSlowRedirect(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg[token.TypeSlowRedirect]
	require.True(t, ok, "expected slowredirect generator registered")
	require.NotNil(t, g)
	require.Equal(t, token.TypeSlowRedirect, g.Type())
}

func TestBuild_RegistersDocx(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg[token.TypeDocx]
	require.True(t, ok, "expected docx generator registered")
	require.NotNil(t, g)
	require.Equal(t, token.TypeDocx, g.Type())
}

func TestBuild_RegistersPDF(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg[token.TypePDF]
	require.True(t, ok, "expected pdf generator registered")
	require.NotNil(t, g)
	require.Equal(t, token.TypePDF, g.Type())
}

func TestBuild_RegistersKubeconfig(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg[token.TypeKubeconfig]
	require.True(t, ok, "expected kubeconfig generator registered")
	require.NotNil(t, g)
	require.Equal(t, token.TypeKubeconfig, g.Type())
}

func TestBuild_RegistersEnvfile(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg[token.TypeEnvfile]
	require.True(t, ok, "expected envfile generator registered")
	require.NotNil(t, g)
	require.Equal(t, token.TypeEnvfile, g.Type())
}

func TestBuild_RegistersMySQL(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg[token.TypeMySQL]
	require.True(t, ok, "expected mysql generator registered")
	require.NotNil(t, g)
	require.Equal(t, token.TypeMySQL, g.Type())
}

func TestBuild_UnknownTypeReturnsZeroValue(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg["nonexistent-type"]
	require.False(t, ok, "unknown type must not be present")
	require.Nil(t, g, "map zero value for missing key must be nil interface")
}

func TestBuild_MySQLUsesConfiguredPublicAddress(t *testing.T) {
	reg := registry.Build(registry.Config{
		BaseURL:         testBaseURL,
		MySQLPublicHost: "canary.example.com",
		MySQLPublicPort: 13306,
	})
	g, ok := reg[token.TypeMySQL]
	require.True(t, ok)

	tok := &token.Token{ID: "abc", Type: token.TypeMySQL}
	art, err := g.Generate(context.Background(), tok, testBaseURL)
	require.NoError(t, err)
	require.Equal(
		t,
		"mysql://canary_abc@canary.example.com:13306/internal_db",
		art.ConnectionString,
		"mysql connection string must reflect configured public host:port",
	)
}

func TestBuild_AllSevenGeneratorsRegistered(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	require.Len(
		t,
		reg,
		7,
		"Phase 8 closes the generator set with all 7 types registered (webbug, slowredirect, docx, pdf, kubeconfig, envfile, mysql)",
	)

	for _, ty := range []token.Type{
		token.TypeWebbug,
		token.TypeSlowRedirect,
		token.TypeDocx,
		token.TypePDF,
		token.TypeKubeconfig,
		token.TypeEnvfile,
		token.TypeMySQL,
	} {
		_, ok := reg[ty]
		require.True(t, ok, "type %q must be registered", ty)
	}
}
