// ©AngelaMos | 2026
// generator_test.go

package kubeconfig_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/kubeconfig"
)

const (
	testBaseURL             = "https://canary.example.com"
	expectedKubeconfigMIME  = "application/yaml"
	defaultFilenameValue    = "kubeconfig"
	defaultClusterNameValue = "prod-cluster"
	defaultUserNameValue    = "svc-backup-reader"
)

type kubeconfigSchema struct {
	APIVersion     string `yaml:"apiVersion"`
	Kind           string `yaml:"kind"`
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server string `yaml:"server"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token string `yaml:"token"`
		} `yaml:"user"`
	} `yaml:"users"`
}

func newKubeconfigToken(id string) *token.Token {
	return &token.Token{
		ID:           id,
		ManageID:     "manage-" + id,
		Type:         token.TypeKubeconfig,
		Memo:         "unit test kubeconfig",
		AlertChannel: token.ChannelWebhook,
		Enabled:      true,
	}
}

func newKubeconfigTokenWithFilename(id, filename string) *token.Token {
	tok := newKubeconfigToken(id)
	tok.Filename = &filename
	return tok
}

func parseKubeconfig(t *testing.T, content []byte) kubeconfigSchema {
	t.Helper()
	var kc kubeconfigSchema
	require.NoError(
		t,
		yaml.Unmarshal(content, &kc),
		"generated kubeconfig must parse as YAML",
	)
	return kc
}

func TestGenerator_TypeIsKubeconfig(t *testing.T) {
	g := kubeconfig.New()
	require.Equal(t, token.TypeKubeconfig, g.Type())
}

func TestGenerate_ArtifactKindIsText(t *testing.T) {
	g := kubeconfig.New()
	art, err := g.Generate(
		context.Background(),
		newKubeconfigToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)
	require.Equal(t, generators.KindText, art.Kind)
}

func TestGenerate_ContentTypeIsYAML(t *testing.T) {
	g := kubeconfig.New()
	art, err := g.Generate(
		context.Background(),
		newKubeconfigToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)
	require.Equal(t, expectedKubeconfigMIME, art.ContentType)
}

func TestGenerate_Filename(t *testing.T) {
	g := kubeconfig.New()

	t.Run("nil Filename defaults to kubeconfig", func(t *testing.T) {
		art, err := g.Generate(
			context.Background(),
			newKubeconfigToken("abc"),
			testBaseURL,
		)
		require.NoError(t, err)
		require.Equal(t, defaultFilenameValue, art.Filename)
	})

	t.Run(
		"empty Filename pointer defaults to kubeconfig",
		func(t *testing.T) {
			art, err := g.Generate(
				context.Background(),
				newKubeconfigTokenWithFilename("abc", ""),
				testBaseURL,
			)
			require.NoError(t, err)
			require.Equal(t, defaultFilenameValue, art.Filename)
		},
	)

	t.Run(
		"whitespace-only Filename defaults to kubeconfig",
		func(t *testing.T) {
			art, err := g.Generate(
				context.Background(),
				newKubeconfigTokenWithFilename("abc", "   "),
				testBaseURL,
			)
			require.NoError(t, err)
			require.Equal(t, defaultFilenameValue, art.Filename)
		},
	)

	t.Run("set Filename is preserved (trimmed)", func(t *testing.T) {
		art, err := g.Generate(
			context.Background(),
			newKubeconfigTokenWithFilename("abc", "  prod-kubeconfig  "),
			testBaseURL,
		)
		require.NoError(t, err)
		require.Equal(t, "prod-kubeconfig", art.Filename)
	})
}

func TestGenerate_APIServerURL(t *testing.T) {
	g := kubeconfig.New()

	t.Run("base URL trailing slash trimmed", func(t *testing.T) {
		artA, err := g.Generate(
			context.Background(),
			newKubeconfigToken("tk1"),
			"https://canary.example.com",
		)
		require.NoError(t, err)
		artB, err := g.Generate(
			context.Background(),
			newKubeconfigToken("tk1"),
			"https://canary.example.com/",
		)
		require.NoError(t, err)

		kcA := parseKubeconfig(t, artA.Content)
		kcB := parseKubeconfig(t, artB.Content)
		require.Len(t, kcA.Clusters, 1)
		require.Len(t, kcB.Clusters, 1)
		require.Equal(
			t,
			"https://canary.example.com/k/tk1",
			kcA.Clusters[0].Cluster.Server,
		)
		require.Equal(
			t,
			"https://canary.example.com/k/tk1",
			kcB.Clusters[0].Cluster.Server,
		)
	})

	t.Run("base URL subpath preserved", func(t *testing.T) {
		art, err := g.Generate(
			context.Background(),
			newKubeconfigToken("tk2"),
			"https://example.com/canary",
		)
		require.NoError(t, err)
		kc := parseKubeconfig(t, art.Content)
		require.Len(t, kc.Clusters, 1)
		require.Equal(
			t,
			"https://example.com/canary/k/tk2",
			kc.Clusters[0].Cluster.Server,
		)
	})

	t.Run(
		"different token ids produce distinct outputs",
		func(t *testing.T) {
			artA, err := g.Generate(
				context.Background(),
				newKubeconfigToken("aaa"),
				testBaseURL,
			)
			require.NoError(t, err)
			artB, err := g.Generate(
				context.Background(),
				newKubeconfigToken("bbb"),
				testBaseURL,
			)
			require.NoError(t, err)
			require.NotEqual(t, artA.Content, artB.Content)
		},
	)
}

func TestGenerate_YAMLParsesAsKubeconfig(t *testing.T) {
	g := kubeconfig.New()
	art, err := g.Generate(
		context.Background(),
		newKubeconfigToken("abc123"),
		testBaseURL,
	)
	require.NoError(t, err)

	kc := parseKubeconfig(t, art.Content)

	require.Equal(t, "v1", kc.APIVersion)
	require.Equal(t, "Config", kc.Kind)
	require.Equal(t, defaultClusterNameValue, kc.CurrentContext)

	require.Len(t, kc.Clusters, 1)
	require.Equal(t, defaultClusterNameValue, kc.Clusters[0].Name)
	require.Equal(
		t,
		"https://canary.example.com/k/abc123",
		kc.Clusters[0].Cluster.Server,
	)

	require.Len(t, kc.Contexts, 1)
	require.Equal(t, defaultClusterNameValue, kc.Contexts[0].Name)
	require.Equal(
		t,
		defaultClusterNameValue,
		kc.Contexts[0].Context.Cluster,
	)
	require.Equal(t, defaultUserNameValue, kc.Contexts[0].Context.User)

	require.Len(t, kc.Users, 1)
	require.Equal(t, defaultUserNameValue, kc.Users[0].Name)
	require.Equal(t, "abc123", kc.Users[0].User.Token)
}

func TestGenerate_TokenIDEmbeddedAsBearer(t *testing.T) {
	g := kubeconfig.New()
	art, err := g.Generate(
		context.Background(),
		newKubeconfigToken("super-secret-bearer-id"),
		testBaseURL,
	)
	require.NoError(t, err)
	require.Contains(
		t,
		string(art.Content),
		"super-secret-bearer-id",
		"kubeconfig must embed the token ID as the bearer token",
	)
}

func TestGenerate_ContentEndsWithNewline(t *testing.T) {
	g := kubeconfig.New()
	art, err := g.Generate(
		context.Background(),
		newKubeconfigToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)
	require.True(
		t,
		strings.HasSuffix(string(art.Content), "\n"),
		"generated YAML must end with a newline (POSIX convention)",
	)
}
