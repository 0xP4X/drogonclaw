package agent

import (
	"strings"
	"testing"
)

func TestIsFastPhaseTool(t *testing.T) {
	fast := []string{"run_nmap", "run_subfinder", "run_httpx", "run_gobuster", "run_ffuf", "run_nuclei", "osint_certs", "web_search"}
	for _, name := range fast {
		if !isFastPhaseTool(name) {
			t.Errorf("expected %q to be classified fast-phase", name)
		}
	}
	slow := []string{"shell_execute", "run_exploit", "run_msfvenom", "write_and_run_script", "ask_operator", "generate_fud_payload"}
	for _, name := range slow {
		if isFastPhaseTool(name) {
			t.Errorf("expected %q NOT to be classified fast-phase", name)
		}
	}
}

func TestAppendToolEvidence(t *testing.T) {
	o := &Orchestrator{}
	for i := 0; i < 10; i++ {
		o.appendToolEvidence("run_nmap", strings.Repeat("x", 8000))
	}
	if len(o.recentToolOutputs) != 6 {
		t.Fatalf("expected evidence window of 6, got %d", len(o.recentToolOutputs))
	}
	for _, rec := range o.recentToolOutputs {
		if len(rec.output) > 6000 {
			t.Fatalf("evidence entry not truncated: %d bytes", len(rec.output))
		}
	}

	o.appendToolEvidence("", "")
	if len(o.recentToolOutputs) != 6 {
		t.Fatalf("empty evidence should be skipped, got window %d", len(o.recentToolOutputs))
	}

	built := buildToolEvidence(o.recentToolOutputs)
	if !strings.Contains(built, "=== run_nmap ===") {
		t.Fatal("buildToolEvidence missing tool header")
	}
}

func TestProviderFastFallback(t *testing.T) {
	// With only a primary model configured, HasFast must be false and the fast
	// tier must fall back to the primary (no panic, no distinct model).
	p := &Provider{model: "primary", fastModel: ""}
	if p.HasFast() {
		t.Fatal("expected HasFast()==false when no fast model configured")
	}
	if p.fastModel != "" {
		t.Fatal("expected empty fast model")
	}

	// Distinct fast model => HasFast true; identical => false.
	p2 := &Provider{model: "primary", fastModel: "primary"}
	if p2.HasFast() {
		t.Fatal("expected HasFast()==false when fast model equals primary")
	}
	p3 := &Provider{model: "primary", fastModel: "fast-cheap"}
	if !p3.HasFast() {
		t.Fatal("expected HasFast()==true with distinct fast model")
	}
}

func TestTrimForVerification(t *testing.T) {
	long := strings.Repeat("a", 5000)
	if len(trimForVerification(long)) != 4000 {
		t.Fatal("expected trim to 4000 chars")
	}
	short := "ok"
	if trimForVerification(short) != short {
		t.Fatal("short strings must pass through unchanged")
	}
}

func TestBuildResultsAppendix(t *testing.T) {
	recs := []toolOutputEvidence{
		{tool: "old", output: strings.Repeat("o", 200)},
		{tool: "run_subfinder", output: "sub-a\nsub-b\nsub-c"},
	}
	app := buildResultsAppendix(recs)
	if !strings.Contains(app, "[run_subfinder]") {
		t.Fatal("expected most-recent tool output first in the appendix")
	}
	if idx := len(app) - 1; idx < 0 || strings.Contains(app[idx:], "[old]") {
		t.Fatal("expected the most-recent block to be listed before the older one")
	}
	if !strings.Contains(app, "sub-a\nsub-b\nsub-c") {
		t.Fatal("expected the subdomain list to be included verbatim")
	}

	big := []toolOutputEvidence{{tool: "huge", output: strings.Repeat("x", resultsAppendixMax*2)}}
	app = buildResultsAppendix(big)
	if len(app) > resultsAppendixMax {
		t.Fatalf("appendix exceeds budget: %d", len(app))
	}
}

func TestCanonicalToolArgsIgnoresShellRedirection(t *testing.T) {
	a := `{"command":"iwconfig","timeout":10}`
	b := `{"command":"iwconfig 2>&1","timeout":10}`
	if canonicalToolArgs("shell_execute", a) != canonicalToolArgs("shell_execute", b) {
		t.Fatal("iwconfig and iwconfig 2>&1 must canonicalize identically")
	}
	c := `{"command":"iwgetid -r","cleanupCommand":"echo done"}`
	d := `{"command":"iwgetid -r","cleanupCommand":"echo other"}`
	if canonicalToolArgs("shell_execute", c) != canonicalToolArgs("shell_execute", d) {
		t.Fatal("same command with different cleanup metadata must canonicalize identically")
	}
	e := `{"command":"iwgetid"}`
	if canonicalToolArgs("shell_execute", c) == canonicalToolArgs("shell_execute", e) {
		t.Fatal("different commands must not canonicalize identically")
	}
}

func TestIsSimpleFactualQuery(t *testing.T) {
	for _, q := range []string{
		"what wifi name are we connected to",
		"hi i am jogon, please what wifi name are we connected to",
		"what is the hostname",
		"show me the current directory",
	} {
		if !isSimpleFactualQuery(q) {
			t.Errorf("expected simple factual query: %q", q)
		}
	}
	for _, q := range []string{
		"scan 10.0.0.0/24 for open ports",
		"find subdomains of example.com",
		"exploit the target at 192.168.1.10",
		"run a full pentest report with tactical assessment of the findings",
	} {
		if isSimpleFactualQuery(q) {
			t.Errorf("expected NON-simple query: %q", q)
		}
	}
}

func TestResetRunStateScopesEachQuestion(t *testing.T) {
	o := &Orchestrator{}
	o.recordToolCall("shell_execute", `{"command":"iwgetid -r"}`)
	o.appendToolEvidence("shell_execute", "LIBRARY")
	if len(o.recentToolCalls) == 0 || len(o.recentToolOutputs) == 0 {
		t.Fatal("setup failed: expected tracked calls and evidence")
	}
	o.resetRunState()
	if len(o.recentToolCalls) != 0 {
		t.Fatal("repeat-call tracking must reset for a new question")
	}
	if len(o.recentToolOutputs) != 0 {
		t.Fatal("evidence window must reset so a new question verifies against its own tools")
	}
}

func TestNeedsEvidenceReview(t *testing.T) {
	memEvidence := []toolOutputEvidence{{tool: "update_neural_memory", output: "[Memory] Acknowledged Operator identity: jiggon."}}
	capabilities := "I'm DrogonClaw with recon, exploitation, payload generation, and vulnerability scanning. What task can I help with?"
	if needsEvidenceReview(capabilities, memEvidence) {
		t.Fatal("capability listing with no findings evidence must skip review")
	}
	subEvidence := []toolOutputEvidence{{tool: "run_subfinder", output: "[SUBFINDER — knust.edu.gh] Found 469 subdomains:\na.knust.edu.gh"}}
	if needsEvidenceReview("Found 469 subdomains", subEvidence) {
		t.Fatal("short summary without result patterns must skip review even with findings evidence")
	}
	if !needsEvidenceReview("Host 216.198.79.1 has ports open", subEvidence) {
		t.Fatal("short answer citing an observed IP must be reviewed")
	}
	handleEvidence := []toolOutputEvidence{{tool: "profile_target", output: "[PASSIVE TARGET PROFILE]\nA: 216.198.79.1"}}
	if needsEvidenceReview("Could you please provide your handle or alias?", handleEvidence) {
		t.Fatal("conversational reply must skip review even when evidence holds findings")
	}
	if needsEvidenceReview("", subEvidence) {
		t.Fatal("empty answer must skip review")
	}
	if needsEvidenceReview("hello", nil) {
		t.Fatal("answer without evidence must skip review")
	}
	if !needsEvidenceReview(strings.Repeat("report ", 200), memEvidence) {
		t.Fatal("long mission report must always be reviewed")
	}
}

func TestIsDeferralAnswer(t *testing.T) {
	for _, s := range []string{
		"Please stand by while I collect the results.",
		"I'm currently gathering information through multiple sources.",
		"I'll provide the report once the data is returned.",
	} {
		if !isDeferralAnswer(s) {
			t.Errorf("expected deferral: %q", s)
		}
	}
	for _, s := range []string{
		"Connected to LIBRARY (wlan0).",
		"Found 469 subdomains, full list above.",
		"TARGET UNREACHABLE — all tools reported connection failures.",
	} {
		if isDeferralAnswer(s) {
			t.Errorf("expected final answer, not deferral: %q", s)
		}
	}
}

func TestExtractKnownAnswer(t *testing.T) {
	recs := []toolOutputEvidence{
		{tool: "shell_execute", output: "lo        no wireless extensions."},
		{tool: "shell_execute", output: "wlan0     IEEE 802.11  ESSID:\"LIBRARY\"\n  Mode:Managed"},
	}
	if got := extractKnownAnswer(recs); got != "LIBRARY" {
		t.Fatalf("expected LIBRARY, got %q", got)
	}
	bare := []toolOutputEvidence{{tool: "shell_execute", output: "LIBRARY"}}
	if got := extractKnownAnswer(bare); got != "LIBRARY" {
		t.Fatalf("expected bare LIBRARY, got %q", got)
	}
	if got := extractKnownAnswer(nil); got != "" {
		t.Fatalf("expected empty answer without evidence, got %q", got)
	}
}
