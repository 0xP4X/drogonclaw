package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0xP4X/drogonclaw-go/internal/memory"
)

func TestUpdateNeuralMemoryOperatorBypassesValidator(t *testing.T) {
	r := &ToolRegistry{validator: NewEvidenceValidator(&Provider{}), graph: memory.NewGraph("test_op_bypass"), builtins: make(map[string]BuiltinFn)}
	r.registerBuiltins()
	r.recentEvidence = append(r.recentEvidence, toolEvidence{Tool: "osint_dns", Summary: "dns data", Timestamp: time.Now()})
	out := r.builtins["update_neural_memory"](context.Background(), map[string]any{
		"id": "operator", "label": "Operator", "data": `{"alias": "jigon"}`,
	})
	if strings.Contains(out, "[Rejected]") {
		t.Fatalf("operator identity must never be validator-rejected, got: %s", out)
	}
	if got := r.graph.GetOperatorProfile().Name; got != "jigon" {
		t.Fatalf("expected operator name jigon extracted from JSON, got %q", got)
	}
}

func TestHealthStatusBuiltin(t *testing.T) {
	r := &ToolRegistry{builtins: make(map[string]BuiltinFn)}
	r.registerBuiltins()
	out := r.builtins["health_status"](context.Background(), map[string]any{})
	if !strings.Contains(out, "DROGONCLAW SYSTEM DIAGNOSTICS") {
		t.Fatalf("expected diagnostics header, got: %s", out)
	}
	if !strings.Contains(out, "Overall Tool Readiness:") {
		t.Fatalf("expected readiness line, got: %s", out)
	}
	if strings.Contains(out, "searchsploit") && strings.Contains(out, "No Results") {
		t.Fatal("health_status must not fall through to exploit search")
	}
}

func TestBuildMemoryEdgesInfersTargetRelationship(t *testing.T) {
	props := map[string]any{"target_id": "target:example.com"}

	edges := buildMemoryEdges("port:example.com:443", "Port", props, "", "", "")

	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].SourceID != "target:example.com" {
		t.Fatalf("unexpected source id: %s", edges[0].SourceID)
	}
	if edges[0].TargetID != "port:example.com:443" {
		t.Fatalf("unexpected target id: %s", edges[0].TargetID)
	}
	if edges[0].Relationship != "HAS_PORT" {
		t.Fatalf("unexpected relationship: %s", edges[0].Relationship)
	}
}

func TestBuildMemoryEdgesUsesExplicitRelationship(t *testing.T) {
	edges := buildMemoryEdges("vuln:log4shell", "Vulnerability", nil, "service:ldap", "", "HAS_VULNERABILITY")

	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].SourceID != "service:ldap" || edges[0].TargetID != "vuln:log4shell" {
		t.Fatalf("unexpected edge: %+v", edges[0])
	}
	if edges[0].Relationship != "HAS_VULNERABILITY" {
		t.Fatalf("unexpected relationship: %s", edges[0].Relationship)
	}
}

func TestBuildNmapFlagsNoDuplicatePortFlag(t *testing.T) {
	// Regression: passing an explicit ports value must not produce two -p
	// options, which makes nmap abort with "Only 1 -p option allowed".
	cases := []struct {
		mode  string
		ports string
	}{
		{"quick", "32402"},
		{"full", "32402"},
		{"default", "80,443"},
		{"vuln", "8080"},
	}
	for _, c := range cases {
		flags := buildNmapFlags(c.mode, c.ports)
		count := 0
		fields := strings.Fields(flags)
		for i := 0; i < len(fields); i++ {
			if fields[i] == "-p" {
				count++
				// the value must immediately follow
				if i+1 >= len(fields) {
					t.Fatalf("mode=%s ports=%s: -p has no value", c.mode, c.ports)
				}
				i++
			} else if strings.HasPrefix(fields[i], "-p") {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("mode=%s ports=%s: expected exactly 1 -p flag, got %d (flags=%q)", c.mode, c.ports, count, flags)
		}
	}
}

func TestBuildNmapFlagsIncludesPn(t *testing.T) {
	// Hosts that block ICMP must still be scanned; -Pn must be present in every mode.
	for _, mode := range []string{"quick", "udp", "vuln", "stealth", "full", "default", ""} {
		flags := buildNmapFlags(mode, "")
		if !strings.Contains(flags, "-Pn") {
			t.Fatalf("mode=%q: expected -Pn in flags %q", mode, flags)
		}
	}
}

func TestUpdateNeuralMemoryCoercion(t *testing.T) {
	tests := []struct {
		name     string
		data     any
		expected string
	}{
		{
			name:     "string alias JSON",
			data:     `{"alias": "0xp4x"}`,
			expected: "0xp4x",
		},
		{
			name:     "plain string alias",
			data:     "0xp4x",
			expected: "0xp4x",
		},
		{
			name:     "map with alias and handle",
			data:     map[string]any{"alias": "0xp4x", "handle": "0xp4x"},
			expected: "0xp4x",
		},
		{
			name:     "stringified Go map format",
			data:     "map[alias:0xp4x handle:0xp4x operator_type:human]",
			expected: "0xp4x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ToolRegistry{graph: memory.NewGraph("test_coercion_" + tt.name), builtins: make(map[string]BuiltinFn)}
			r.registerBuiltins()
			_ = r.builtins["update_neural_memory"](context.Background(), map[string]any{
				"id": "operator", "label": "Operator", "data": tt.data,
			})
			profile := r.graph.GetOperatorProfile()
			if profile == nil || profile.Name != tt.expected {
				t.Fatalf("for test %q: expected operator name %q, got %+v", tt.name, tt.expected, profile)
			}
		})
	}
}

