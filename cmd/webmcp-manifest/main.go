// webmcp-manifest dumps every registered MCP tool (name, title, description,
// input schema, annotations) as JSON. The output is the single source of
// truth for the in-page WebMCP surface (github.com/alertkick/alertkick-webmcp):
// the browser registers exactly these tools with navigator.modelContext and
// only supplies the execute() bodies, so the two transports cannot drift.
//
// Usage: go run ./cmd/webmcp-manifest > tools.json
package main

import (
	"alertkick-mcp/client"
	"alertkick-mcp/config"
	"alertkick-mcp/tools"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var version = "dev"

type manifestTool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations annotations     `json:"annotations"`
}

type annotations struct {
	ReadOnlyHint    bool `json:"readOnlyHint"`
	DestructiveHint bool `json:"destructiveHint"`
	IdempotentHint  bool `json:"idempotentHint"`
	OpenWorldHint   bool `json:"openWorldHint"`
}

type manifest struct {
	Schema    string         `json:"$schema"`
	Generator string         `json:"generator"`
	Version   string         `json:"version"`
	Tools     []manifestTool `json:"tools"`
}

func main() {
	ctx := context.Background()

	// The client is never called: ListTools only reads registrations.
	c := client.NewTenantClient(&config.Config{TenantDomain: "alertkick.com"}, version, "manifest", "", true)
	server := mcp.NewServer(&mcp.Implementation{Name: "alertkick-mcp", Version: version}, nil)
	tools.RegisterAll(server, c)

	st, ct := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, st, nil); err != nil {
		fail(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "webmcp-manifest", Version: version}, nil).Connect(ctx, ct, nil)
	if err != nil {
		fail(err)
	}
	defer cs.Close()

	m := manifest{
		Schema:    "https://alertkick.com/schemas/webmcp-manifest-v1.json",
		Generator: "alertkick-mcp/cmd/webmcp-manifest",
		Version:   version,
	}
	for t, err := range cs.Tools(ctx, nil) {
		if err != nil {
			fail(err)
		}
		schema, err := json.Marshal(t.InputSchema)
		if err != nil {
			fail(err)
		}
		mt := manifestTool{Name: t.Name, Description: t.Description, InputSchema: schema}
		if a := t.Annotations; a != nil {
			mt.Title = a.Title
			mt.Annotations = annotations{
				ReadOnlyHint:    a.ReadOnlyHint,
				DestructiveHint: a.DestructiveHint == nil || *a.DestructiveHint, // MCP default is true
				IdempotentHint:  a.IdempotentHint,
				OpenWorldHint:   a.OpenWorldHint == nil || *a.OpenWorldHint,
			}
		}
		m.Tools = append(m.Tools, mt)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "webmcp-manifest:", err)
	os.Exit(1)
}
