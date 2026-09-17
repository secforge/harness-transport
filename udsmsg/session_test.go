package udsmsg

import "testing"

// An MCP server's entry has to be identifiable as what it is: the harness it
// belongs to, the server it is, and a kind that does not claim to be a
// session. Registering makes it addressable by name and says nothing more
// than that; registering AS a session would be the impersonation that
// justified not registering at all.
func TestMCPEntryNamesBothHarnessAndServer(t *testing.T) {
	e, err := NewMCPEntry("/run/user/0/cc-socks/4242-a1b2c3d4.sock", "example-mcp-server (build)", "example-mcp-server2")
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "example-mcp-server (build) · mcp:example-mcp-server2" {
		t.Errorf("name = %q, want the harness and the server", e.Name)
	}
	if e.Kind == "interactive" {
		t.Error("an MCP server must not be recorded as an interactive session")
	}
	if e.Kind != "mcp" || e.Entrypoint != "mcp" {
		t.Errorf("kind/entrypoint = %q/%q, want mcp", e.Kind, e.Entrypoint)
	}
}

func TestMCPEntryNameDegradesUsably(t *testing.T) {
	for _, tc := range []struct{ harness, mcp, want string }{
		{"example-mcp-server (build)", "example-mcp-server", "example-mcp-server (build) · mcp:example-mcp-server"},
		{"", "example-mcp-server", "mcp:example-mcp-server"},
		{"example-mcp-server (build)", "", "example-mcp-server (build) · mcp"},
		{"", "", "mcp"},
	} {
		if got := mcpEntryName(tc.harness, tc.mcp); got != tc.want {
			t.Errorf("mcpEntryName(%q, %q) = %q, want %q", tc.harness, tc.mcp, got, tc.want)
		}
	}
}
