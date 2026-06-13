// ©AngelaMos | 2026
// generator.go

package mysql

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
)

const (
	defaultPublicHost = "localhost"
	defaultPublicPort = 3306
	defaultDatabase   = "internal_db"

	connectionStringFmt = "mysql://%s@%s:%d/%s"
)

type Generator struct {
	publicHost string
	publicPort int
	database   string
}

func New() *Generator {
	return NewWithAddress(defaultPublicHost, defaultPublicPort)
}

func NewWithAddress(host string, port int) *Generator {
	return &Generator{
		publicHost: host,
		publicPort: port,
		database:   defaultDatabase,
	}
}

func (g *Generator) Type() token.Type { return token.TypeMySQL }

func (g *Generator) Generate(
	_ context.Context,
	t *token.Token,
	_ string,
) (generators.Artifact, error) {
	username := mysqlUsernamePrefix + t.ID

	newMeta, err := setMySQLUsername(t.Metadata, username)
	if err != nil {
		return generators.Artifact{}, fmt.Errorf(
			"mysql: persist username: %w",
			err,
		)
	}
	t.Metadata = newMeta

	connStr := fmt.Sprintf(
		connectionStringFmt,
		username,
		g.publicHost,
		g.publicPort,
		g.database,
	)

	return generators.Artifact{
		Kind:             generators.KindConnectionString,
		ConnectionString: connStr,
	}, nil
}

func (g *Generator) Trigger(
	_ context.Context,
	_ *token.Token,
	_ *http.Request,
) (*event.Event, *generators.TriggerResponse, error) {
	return nil, nil, ErrHTTPTriggerNotSupported
}

func setMySQLUsername(
	metadata json.RawMessage,
	username string,
) (json.RawMessage, error) {
	m := make(map[string]json.RawMessage)
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &m); err != nil {
			m = make(map[string]json.RawMessage)
		}
	}
	val, err := json.Marshal(username)
	if err != nil {
		return nil, fmt.Errorf("marshal mysql_username: %w", err)
	}
	m[extraMySQLUsername] = val
	out, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal merged metadata: %w", err)
	}
	return out, nil
}
