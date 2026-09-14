package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/0xP4X/drogonclaw-go/internal/core"
	"github.com/0xP4X/drogonclaw-go/internal/memory"
	"github.com/openai/openai-go"
)

// EventType classifies events emitted during agent execution.
type EventType string

const (
	EvThinking  EventType = "thinking"
	EvPlan      EventType = "plan"
	EvToolStart EventType = "tool_start"
	EvToolDone  EventType = "tool_done"
	EvToken     EventType = "token"
	EvDone      EventType = "done"
	EvError     EventType = "error"
	EvStatus    EventType = "status"
	// EvApproval is emitted before a long-running, low-risk tool executes in
	// manual mode so the operator can accept or skip it.
	EvApproval EventType = "approval"
)

// Event is emitted to the TUI during agent execution.
type Event struct {
	Type      EventType
	Tool      string
	Args      string
	Result    string
	Content   string
	Plan      *core.MissionPlan
	StepIndex int
	StepTotal int
}

// Orchestrator is the DrogonClaw agent — a hand-rolled ReAct loop.
type Orchestrator struct {
	provider      *Provider
	tools         *ToolRegistry
	history       []openai.ChatCompletionMessageParamUnion
	sysPrompt     string
	maxIterations int

	// Session state
	Autopilot bool
	Telemetry bool
	SessionID string

	// Subsystems
	missionPlanner *core.MissionPlanner
	actions        *memory.ActionJournal
	graph          *memory.Graph

	// SubagentManager enables parallel task execution (inspired by Hermes Agent)
	subagents *SubagentManager

	// Repetition detection: tracks recent tool calls to break infinite loops
	recentToolCalls []toolCallRecord

	// Per-phase model routing: after a round whose tool calls were exclusively
	// fast/recon-class, the next reasoning turn is served by the fast tier.
	fastPhaseNext bool

	// recentToolOutputs feeds the auto-verify step, which re-checks the
	// agent's final claims against the raw tool evidence it actually gathered.
	recentToolOutputs []toolOutputEvidence
}

type toolOutputEvidence struct {
	tool   string
	output string
}

// fastPhaseTools classifies high-volume, low-stakes enumeration tools. Reasoning
// that immediately follows one of these only needs to parse and summarize
// scanner output, so it is safe to serve from the fast/cheap model tier.
var fastPhaseTools = map[string]bool{
	"run_nmap":             true,
	"run_nuclei":           true,
	"run_gobuster":         true,
	"run_ffuf":             true,
	"run_sqlmap":           true,
	"run_subfinder":        true,
	"run_httpx":            true,
	"run_forensics_triage": true,
	"fuzz_endpoint":        true,
	"profile_target":       true,
	"osint_certs":          true,
	"osint_dns":            true,
	"osint_whois":          true,
	"osint_shodan":         true,
	"osint_virustotal":     true,
	"osint_emails":         true,
	"osint_github_dork":    true,
	"lookup_cve":           true,
	"refresh_cve_feeds":    true,
	"fetch_url":            true,
	"web_search":           true,
	"replay_request":       true,
}

func isFastPhaseTool(name string) bool {
	return fastPhaseTools[name]
}

// appendToolEvidence keeps a sliding window of the most recent raw tool outputs
// (bounded) for the auto-verify step.
func (o *Orchestrator) appendToolEvidence(tool, output string) {
	if output == "" {
		return
	}
	if len(output) > 6000 {
		output = output[:6000]
	}
	o.recentToolOutputs = append(o.recentToolOutputs, toolOutputEvidence{tool: tool, output: output})
	if len(o.recentToolOutputs) > 6 {
		o.recentToolOutputs = o.recentToolOutputs[len(o.recentToolOutputs)-6:]
	}
}

func buildToolEvidence(recs []toolOutputEvidence) string {
	var sb strings.Builder
	for _, r := range recs {
		sb.WriteString("=== " + r.tool + " ===\n")
		sb.WriteString(r.output)
		sb.WriteString("\n")
	}
	return sb.String()
}

// resultsAppendixMax caps how much raw tool output is appended to the final
// deliverable so long scans cannot blow up the operator's report (Telegram
// chunks long messages, but bounded output keeps the summary readable).
const resultsAppendixMax = 6000

// buildResultsAppendix renders the most-recent raw tool outputs (e.g. the full
// subdomain list) for the operator. Unlike buildToolEvidence it walks the
// window backwards so the newest results appear first, and truncates each block
// so a single noisy tool cannot swallow the whole appendix.
func buildResultsAppendix(recs []toolOutputEvidence) string {
	var sb strings.Builder
	sb.WriteString("\n\n--- RAW TOOL RESULTS ---\n")
	for i := len(recs) - 1; i >= 0; i-- {
		if sb.Len() >= resultsAppendixMax {
			break
		}
		r := recs[i]
		block := "[" + r.tool + "]\n" + r.output + "\n"
		if len(block) > 4000 {
			block = block[:4000] + "\n…(truncated)…\n"
		}
		if sb.Len()+len(block) > resultsAppendixMax {
			room := resultsAppendixMax - sb.Len()
			if room > 0 {
				sb.WriteString(block[:room])
			}
			break
		}
		sb.WriteString(block)
	}
	return sb.String()
}

type toolCallRecord struct {
	toolName string
	args     string
}

const maxHistoryMessages = 24

// runBudget caps the total wall-clock time of one Execute loop. It prevents
// indefinite hangs and is separate from the per-command timeout. Thirty minutes
// is enough for a complex OSINT or multi-step mission; adjust via config if needed.
const runBudget = 30 * time.Minute

// longRunningTools maps low-risk but time-consuming tool names to an estimated
// runtime. When not in autopilot, the orchestrator pauses before running one of
// these and asks the operator to accept or skip it (see EvApproval).
var longRunningTools = map[string]time.Duration{
	"run_gobuster":                2 * time.Minute,
	"run_ffuf":                    2 * time.Minute,
	"run_nuclei":                  2 * time.Minute,
	"run_nmap":                    3 * time.Minute,
	"fuzz_endpoint":               3 * time.Minute,
	"run_subfinder":               1 * time.Minute,
	"run_httpx":                   1 * time.Minute,
	"refresh_cve_feeds":           2 * time.Minute,
	"deep_research":               2 * time.Minute,
	"osint_certs":                 1 * time.Minute,
	"run_forensics_triage":        3 * time.Minute,
	"autonomous_fuzzing_engine":   5 * time.Minute,
	"dynamic_payload_compiler":    5 * time.Minute,
	"advanced_web_exploiter":      5 * time.Minute,
	"headless_browser_automation": 3 * time.Minute,
	"zero_click_exploiter":        5 * time.Minute,
	"async_race_condition_engine": 3 * time.Minute,
	"write_and_run_script":        5 * time.Minute,
	"ghost_wipe_logs":             1 * time.Minute,
	"ghost_secure_delete":         1 * time.Minute,
	"ghost_clear_history":         1 * time.Minute,
}

// isLongRunningTool reports whether a tool is expected to run a long time and,
// if so, returns the estimated duration.
func isLongRunningTool(name string) (time.Duration, bool) {
	if d, ok := longRunningTools[name]; ok {
		return d, true
	}
	// Tool names built dynamically as run_<binary> use the same prefix rules.
	if strings.HasPrefix(name, "run_") {
		return 30 * time.Minute, true
	}
	return 0, false
}

const (
	maxRecentToolCalls  = 8
	repetitionThreshold = 2
)

func (o *Orchestrator) isRepeatedCall(toolName, args string) bool {
	return o.countRecentCalls(toolName, args) >= repetitionThreshold
}

func (o *Orchestrator) countRecentCalls(toolName, args string) int {
	normalized := canonicalToolArgs(toolName, args)
	count := 0
	for _, rec := range o.recentToolCalls {
		if rec.toolName == toolName && rec.args == normalized {
			count++
		}
	}
	return count
}

func (o *Orchestrator) recordToolCall(toolName, args string) {
	o.recentToolCalls = append(o.recentToolCalls, toolCallRecord{toolName: toolName, args: canonicalToolArgs(toolName, args)})
	if len(o.recentToolCalls) > maxRecentToolCalls {
		o.recentToolCalls = o.recentToolCalls[len(o.recentToolCalls)-maxRecentToolCalls:]
	}
}

func canonicalToolArgs(toolName, raw string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return strings.TrimSpace(raw)
	}
	if toolName == "shell_execute" {
		if cmd, ok := m["command"].(string); ok {
			return "command=" + normalizeShellCommand(cmd)
		}
	}
	return normalizeArgs(raw)
}

func normalizeShellCommand(cmd string) string {
	s := strings.TrimSpace(cmd)
	s = strings.ReplaceAll(s, "2>&1", "")
	s = strings.ReplaceAll(s, "2>/dev/null", "")
	s = strings.ReplaceAll(s, "2> /dev/null", "")
	s = strings.ReplaceAll(s, "| cat", "")
	return strings.Join(strings.Fields(s), " ")
}

func isSimpleFactualQuery(msg string) bool {
	low := strings.ToLower(strings.TrimSpace(msg))
	if low == "" || len(strings.Fields(low)) > 25 {
		return false
	}
	if extractTargetFromMessage(msg) != "" {
		return false
	}
	for _, kw := range []string{
		"wifi", "wi-fi", "ssid", "essid", "what network", "which network",
		"connected to", "hostname", "whoami", "current director", "working director",
		"what is my ip", "my ip address", "what user", "which user",
	} {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

var essidRe = regexp.MustCompile(`(?i)(?:ESSID:|yes:)([^\r\n"]+)`)

func isDeferralAnswer(s string) bool {
	low := strings.ToLower(s)
	for _, p := range []string{
		"stand by", "standby", "please wait", "still working",
		"currently gathering", "currently collecting", "currently running",
		"once the data", "once the results", "in progress",
		"gathering information", "will report back",
	} {
		if strings.Contains(low, p) {
			return true
		}
	}
	return false
}

func extractKnownAnswer(recs []toolOutputEvidence) string {
	for i := len(recs) - 1; i >= 0; i-- {
		if m := essidRe.FindStringSubmatch(recs[i].output); m != nil {
			return strings.TrimSpace(m[1])
		}
	}
	for i := len(recs) - 1; i >= 0; i-- {
		t := strings.TrimSpace(recs[i].output)
		if strings.HasPrefix(t, "[Dedup]") || strings.HasPrefix(t, "[Blocked]") || strings.HasPrefix(t, "[Error]") {
			continue
		}
		low := strings.ToLower(t)
		if strings.Contains(low, "no wireless") || strings.Contains(low, "not found") || strings.Contains(low, "error") {
			continue
		}
		if !strings.Contains(t, "\n") && len(t) > 0 && len(t) <= 32 {
			if regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,31}$`).MatchString(t) {
				return t
			}
		}
	}
	return ""
}

func (o *Orchestrator) clearRecentCalls() {
	o.recentToolCalls = nil
}

func (o *Orchestrator) resetRunState() {
	o.recentToolCalls = nil
	o.recentToolOutputs = nil
}

func normalizeArgs(raw string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return raw
	}
	b, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return string(b)
}

// NewOrchestrator creates the agent core.
func NewOrchestrator(provider *Provider, tools *ToolRegistry, sysPrompt, sessionID string, graph *memory.Graph, maxIterations int) *Orchestrator {
	return NewOrchestratorWithJournal(provider, tools, sysPrompt, sessionID, graph, memory.NewActionJournal(sessionID), maxIterations)
}

// NewOrchestratorWithJournal permits the primary UI to use a stable journal
// name across application restarts while worker agents keep isolated journals.
func NewOrchestratorWithJournal(provider *Provider, tools *ToolRegistry, sysPrompt, sessionID string, graph *memory.Graph, actions *memory.ActionJournal, maxIterations int) *Orchestrator {
	if maxIterations <= 0 {
		maxIterations = 20
	}
	o := &Orchestrator{
		provider:       provider,
		tools:          tools,
		sysPrompt:      sysPrompt,
		maxIterations:  maxIterations,
		SessionID:      sessionID,
		missionPlanner: core.NewMissionPlanner(provider, graph),
		actions:        actions,
		graph:          graph,
		subagents:      NewSubagentManager(provider, tools, 5),
	}
	if tools != nil {
		tools.SetSubagents(o.subagents)
	}
	return o
}

func (o *Orchestrator) GetProvider() *Provider {
	return o.provider
}

func (o *Orchestrator) GetTools() *ToolRegistry {
	return o.tools
}

// GetSubagents returns the subagent manager for parallel execution.
func (o *Orchestrator) GetSubagents() *SubagentManager {
	return o.subagents
}

// ExecuteParallelTasks runs multiple independent tasks concurrently and merges
// the results. This is the primary way to speed up recon and scanning.
func (o *Orchestrator) ExecuteParallelTasks(ctx context.Context, tasks []SubagentTask, events chan<- Event) string {
	results := o.subagents.ExecuteParallel(ctx, tasks, events)
	return FormatResultsForLLM(results)
}

// UpdateSystemPrompt hot-swaps the system prompt (e.g., after /persona or /stealth).
func (o *Orchestrator) UpdateSystemPrompt(prompt string) {
	o.sysPrompt = prompt
}

// NewSession wipes conversation history.
func (o *Orchestrator) NewSession() {
	o.history = nil
	if o.actions != nil {
		o.actions.Clear()
	}
}

// retainHistory keeps conversations useful while bounding prompt size and RAM
// use in long-running interactive sessions. Each exchange contributes a user
// and assistant message, so retaining an even number preserves turn pairs.
func (o *Orchestrator) retainHistory() {
	if len(o.history) > maxHistoryMessages {
		o.history = append([]openai.ChatCompletionMessageParamUnion(nil), o.history[len(o.history)-maxHistoryMessages:]...)
	}
}

func (o *Orchestrator) Recovery() *memory.ActionRecord {
	if o.actions == nil {
		return nil
	}
	return o.actions.Recovery()
}

// Resume re-enters the normal planner with the durable checkpoint as context.
// It never claims an interrupted external tool completed, preventing unsafe
// duplicate actions from being hidden from the operator.
func (o *Orchestrator) Resume(ctx context.Context, events chan<- Event) error {
	recovery := o.Recovery()
	if recovery == nil {
		return fmt.Errorf("there is no interrupted action to resume")
	}
	context := fmt.Sprintf("Resume the interrupted mission: %s\nCompleted checkpoints: %s\nInterrupted tool (its outcome is unknown; verify before retrying): %s\nContinue from the safest next step without repeating completed work.", recovery.Objective, strings.Join(recovery.CompletedSteps, " | "), recovery.CurrentTool)
	return o.Execute(ctx, context, events)
}

// Execute runs the ReAct loop for a user message, emitting events to the channel.
// The caller must close or drain the channel.
func (o *Orchestrator) Execute(ctx context.Context, userMsg string, events chan<- Event) error {
	defer close(events)

	// Bound the whole run so a blocked tool, an unanswered approval gate, or a
	// looping model cannot hang the session indefinitely.
	ctx, cancel := context.WithTimeout(ctx, runBudget)
	defer cancel()

	if o.actions != nil {
		o.actions.Begin(userMsg)
	}

	o.resetRunState()

	// 1. Mission Planning Phase
	events <- Event{Type: EvThinking, Content: "Analyzing objective and generating execution plan..."}
	plan, err := o.missionPlanner.GeneratePlan(ctx, userMsg)
	if err == nil && plan != nil && plan.IsValidMission {
		events <- Event{Type: EvPlan, Plan: plan, Content: "Mission plan generated"}
		var planLines []string
		for i, step := range plan.Steps {
			planLines = append(planLines, fmt.Sprintf("%d. %s (Target: %s)", i+1, step.Action, step.TargetAssetID))
		}
		if o.actions != nil {
			o.actions.SetPlan(planLines)
		}
		events <- Event{Type: EvToken, Content: fmt.Sprintf("```\n[MISSION PLAN GENERATED]\nObjective: %s\nSteps:\n%s\n```\n\n", plan.Objective, strings.Join(planLines, "\n"))}
	} else {
		events <- Event{Type: EvStatus, Content: "Planning fallback engaged; proceeding with direct reasoning..."}
	}

	memoryCtx := ""
	if o.graph != nil {
		memoryCtx = o.graph.Snapshot()
	}

	// Inject learned attack patterns from previous successes
	learnedCtx := ""
	if o.tools != nil && o.tools.skillLearner != nil {
		target := extractTargetFromMessage(userMsg)
		if target != "" {
			learnedCtx = o.tools.GetLearnedContext(target)
		}
	}

	combinedCtx := memoryCtx
	if learnedCtx != "" {
		if combinedCtx != "" {
			combinedCtx += "\n\n" + learnedCtx
		} else {
			combinedCtx = learnedCtx
		}
	}

	messages := BuildMessages(o.sysPrompt, combinedCtx, o.history, userMsg)

	// Inject mission plan into context so the LLM can follow it
	if err == nil && plan != nil && plan.IsValidMission && len(plan.Steps) > 0 {
		var planBlock strings.Builder
		planBlock.WriteString("\n\n--- MISSION PLAN (follow this execution order) ---\n")
		for i, step := range plan.Steps {
			planBlock.WriteString(fmt.Sprintf("%d. [%s] %s → Target: %s | Expected: %s\n",
				i+1, step.Status, step.Action, step.TargetAssetID, step.ExpectedOutcome))
		}
		planBlock.WriteString("--- END MISSION PLAN ---\n")
		planBlock.WriteString("Track your progress through these steps. Mark steps complete as you verify outcomes.\n")
		messages = append(messages[:1], append([]openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage(planBlock.String()),
		}, messages[1:]...)...)
	}

	// Track this turn in history so recovery resumes with context instead of
	// feeling like a brand-new run.
	o.history = append(o.history, openai.UserMessage(userMsg))
	o.retainHistory()

	// Snapshot history length so we can recover this turn's messages on error
	// without losing the in-flight tool-call context.
	historyLen := len(o.history)

	o.fastPhaseNext = false
	maxIter := o.maxIterations
	simpleQuery := isSimpleFactualQuery(userMsg)
	if simpleQuery && maxIter > 6 {
		maxIter = 6
	}
	shellCalls := 0
	answerNudged := false
	runFindings := 0
	nonFindingStreak := 0
	finalizeNudged := false
	blockedStreak := 0
	blockedNudged := false
	toolsExecutedThisRun := 0
	deferralNudged := false
	compactor := NewAutoCompactor(o.provider, o.graph)

	for i := 0; i < maxIter; i++ {
		// Auto-Compact context if history exceeds threshold
		if compactor.ShouldCompact(messages) {
			compacted, _, compErr := compactor.Compact(ctx, messages)
			if compErr == nil && len(compacted) > 0 {
				messages = compacted
				events <- Event{Type: EvStatus, Content: "Auto-compacting conversation history to preserve context window..."}
			}
		}

		var resp *CompletionResponse
		var err error
		var usedFast bool
		if o.fastPhaseNext && o.provider.HasFast() {
			resp, err = o.provider.CompleteFast(ctx, messages, o.tools.Definitions())
			usedFast = true
		} else {
			resp, err = o.provider.Complete(ctx, messages, o.tools.Definitions())
		}
		if err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				events <- Event{Type: EvError, Content: fmt.Sprintf("Run budget exceeded (%s). The run was stalled (likely waiting on an unanswered approval or a hung tool). Run in autopilot to skip approvals, or raise runBudget.", runBudget)}
				if o.actions != nil {
					o.actions.Finish("failed", "run budget exceeded")
				}
				return context.DeadlineExceeded
			}
			// Preserve this turn's conversation state so a follow-up like
			// "continue" resumes with context instead of feeling like a new run.
			startIdx := 1
			if memoryCtx != "" {
				startIdx = 2
			}
			if len(messages) > startIdx+historyLen {
				o.history = append(o.history, messages[startIdx+historyLen:]...)
				o.retainHistory()
			}
			if o.actions != nil {
				o.actions.Finish("failed", err.Error())
			}
			events <- Event{Type: EvError, Content: fmt.Sprintf("LLM error: %v", err)}
			return err
		}

		// Append assistant message to history
		messages = append(messages, resp.Message.ToParam())
		o.history = append(o.history, resp.Message.ToParam())
		o.retainHistory()

		// --- Fallback Parser for Raw JSON Tool Calls ---
		// Some uncensored models fail to use the native ToolCalls API and output JSON directly.
		if len(resp.ToolCalls) == 0 && (strings.Contains(resp.Message.Content, `{"name"`) || strings.Contains(resp.Message.Content, `{"tool"`)) {
			re := regexp.MustCompile(`(?s)\{"(?:name|tool)"\s*:\s*"[^"]+",\s*"arguments"\s*:\s*\{.*?\}\}`)
			matches := re.FindAllString(resp.Message.Content, -1)

			for i, match := range matches {
				var parsed struct {
					Name      string                 `json:"name"`
					Tool      string                 `json:"tool"`
					Arguments map[string]interface{} `json:"arguments"`
				}
				if err := json.Unmarshal([]byte(match), &parsed); err == nil {
					name := parsed.Name
					if name == "" {
						name = parsed.Tool
					}
					argsBytes, _ := json.Marshal(parsed.Arguments)
					tc := openai.ChatCompletionMessageToolCall{
						ID: fmt.Sprintf("call_fb_%d_%d", time.Now().Unix(), i),
						Function: openai.ChatCompletionMessageToolCallFunction{
							Name:      name,
							Arguments: string(argsBytes),
						},
					}
					resp.ToolCalls = append(resp.ToolCalls, tc)
				}
			}

			if len(resp.ToolCalls) > 0 {
				resp.Message.Content = strings.TrimSpace(re.ReplaceAllString(resp.Message.Content, ""))
			}
		}
		// ---------------------------------------------

		// No tool calls = final answer — stream it
		if len(resp.ToolCalls) == 0 {
			events <- Event{Type: EvStatus, Content: "Composing response..."}
			finalContent := resp.Message.Content

			// If the answering turn was served by the fast tier, re-synthesize
			// the final deliverable with the primary model so the operator's
			// report never ships from the cheap model alone.
			if usedFast {
				refine := "The above draft was produced for speed (fast model tier). " +
					"Revisit it and produce the definitive final report for the operator."
				messages = append(messages, openai.UserMessage(refine))
				if fRes, fErr := o.provider.Complete(ctx, messages, nil); fErr == nil && fRes.Message.Content != "" {
					finalContent = fRes.Message.Content
					if len(o.history) > 0 {
						o.history[len(o.history)-1] = fRes.Message.ToParam()
					}
					o.retainHistory()
				}
			}

			if !deferralNudged && toolsExecutedThisRun > 0 && isDeferralAnswer(finalContent) {
				nudge := "[SYSTEM] The tool results above are already complete — nothing is still running. Synthesize the final report for the operator NOW from these results with NO further tool calls. Do not say 'stand by'."
				messages = append(messages, openai.UserMessage(nudge))
				o.history = append(o.history, openai.UserMessage(nudge))
				o.retainHistory()
				deferralNudged = true
				continue
			}

			// Grounding: deterministically cross-check the final answer's
			// interface/hardware/IP claims against the raw tool evidence this
			// run. Unlike auto-verify below this never invokes the LLM, so it
			// fires on every answer (fast tier included).
			if len(o.recentToolOutputs) > 0 {
				if correction := groundingCorrections(finalContent, o.recentToolOutputs); correction != "" {
					note := "[AUTO-GROUNDING] " + correction
					finalContent += "\n\n" + note
					events <- Event{Type: EvStatus, Content: note}
				}
			}

			if needsEvidenceReview(finalContent, o.recentToolOutputs) && o.tools != nil && o.tools.validator != nil && len(o.recentToolOutputs) > 0 {
				vctx, vcancel := context.WithTimeout(ctx, 25*time.Second)
				ev := buildToolEvidence(o.recentToolOutputs)
				verdict, vErr := o.tools.validator.Validate(vctx, "combined", ev, trimForVerification(finalContent))
				vcancel()
				if vErr == nil {
					vline := fmt.Sprintf("[verdict: %s · confidence %d%%] %s",
						map[bool]string{true: "VALIDATED", false: "UNVERIFIED"}[verdict.IsValid],
						verdict.ConfidenceScore, verdict.Reasoning)
					finalContent += "\n\n[AUTO-VERIFY] " + vline
					if !verdict.IsValid {
						finalContent += "\n[AUTO-VERIFY] Warning: final findings are not backed by recorded tool evidence; treat with caution."
					}
					events <- Event{Type: EvStatus, Content: "Auto-verify: " + vline}
				} else {
					events <- Event{Type: EvStatus, Content: "Auto-verify skipped: " + vErr.Error()}
				}
			}

			if len(o.recentToolOutputs) > 0 && needsEvidenceReview(finalContent, o.recentToolOutputs) {
				finalContent += buildResultsAppendix(o.recentToolOutputs)
			}

			events <- Event{Type: EvToken, Content: finalContent}
			events <- Event{Type: EvDone, Content: finalContent}
			if o.actions != nil {
				o.actions.Finish("completed", "")
			}
			return nil
		}

		// Execute each tool call
		fastRound := true
		for _, tc := range resp.ToolCalls {
			prettyArgs := formatArgs(tc.Function.Arguments)

			if o.isRepeatedCall(tc.Function.Name, tc.Function.Arguments) {
				loopMsg := fmt.Sprintf(
					"[SYSTEM WARNING] You have called %s with the same effective command %d times. The answer is already in your previous tool outputs above. STOP calling tools and answer the operator's original question NOW using the evidence you already have. Do NOT call this tool again.",
					tc.Function.Name, o.countRecentCalls(tc.Function.Name, tc.Function.Arguments))
				messages = append(messages, openai.UserMessage(loopMsg))
				o.history = append(o.history, openai.UserMessage(loopMsg))
				o.retainHistory()
				events <- Event{Type: EvError, Content: fmt.Sprintf("Repetition detected: %s called %d times with same command. Breaking loop — answer with existing evidence.", tc.Function.Name, o.countRecentCalls(tc.Function.Name, tc.Function.Arguments))}
				o.clearRecentCalls()
				continue
			}

			// Optional acceptance gate for long-running, low-risk tools.
			// In autopilot the operator has already delegated authority, so we
			// skip the prompt entirely. Otherwise we surface an approval event
			// with an estimated runtime and block until the operator responds.
			if est, long := isLongRunningTool(tc.Function.Name); long && !o.Autopilot {
				events <- Event{
					Type:    EvApproval,
					Tool:    tc.Function.Name,
					Args:    prettyArgs,
					Content: est.Round(time.Minute).String(),
				}
				events <- Event{Type: EvStatus, Content: fmt.Sprintf("Awaiting operator acceptance to run %s (est. %s)...", tc.Function.Name, est.Round(time.Minute))}
				core.GlobalHitL.RequestApprovalWithDetail(core.ApprovalDuration, est.Round(time.Minute).String())
				if err := core.GlobalHitL.Wait(ctx); err != nil {
					if o.actions != nil {
						o.actions.Finish("interrupted", err.Error())
					}
					return err
				}
				if !core.GlobalHitL.ConsumeApproved() {
					skipMsg := fmt.Sprintf("[Skipped] Operator declined to run %s (long-running tool).", tc.Function.Name)
					events <- Event{Type: EvToolDone, Tool: tc.Function.Name, Result: skipMsg}
					if o.actions != nil {
						o.actions.ToolFinished(tc.Function.Name, skipMsg)
					}
					continue
				}
			}

			events <- Event{Type: EvToolStart, Tool: tc.Function.Name, Args: prettyArgs}
			if o.actions != nil {
				o.actions.ToolStarted(tc.Function.Name, prettyArgs)
			}

			result := o.tools.Execute(ctx, tc.Function.Name, tc.Function.Arguments)
			toolsExecutedThisRun++
			o.recordToolCall(tc.Function.Name, tc.Function.Arguments)
			o.appendToolEvidence(tc.Function.Name, result)
			if !isFastPhaseTool(tc.Function.Name) {
				fastRound = false
			}
			if o.actions != nil {
				o.actions.ToolFinished(tc.Function.Name, result)
			}

			// Deterministic evidence evaluation: the model is told the verified
			// status so it cannot claim success on prose alone. Verified findings
			// are recorded to the loot database with provenance. The footer is
			// appended to the tool result so the LLM sees the verification verdict.
			verified, estatus, reason := o.tools.EvaluateTool(tc.Function.Name, result)
			if verified {
				o.tools.RecordVerifiedFinding()
			}
			displayResult := result
			llmResult := result
			if estatus != "" {
				llmResult += fmt.Sprintf("\n[EVIDENCE: %s — %s]", estatus, reason)
			}
			if strings.HasPrefix(result, "[Dedup]") {
				llmResult += "\n[SYSTEM HINT] This command already ran — its output is reused above. You already have this data. Answer the operator now instead of re-running it."
			}
			if strings.HasPrefix(result, "[Blocked]") {
				llmResult += "\n[SYSTEM HINT] Blocked by policy — do not retry this with tweaked arguments; use the suggested dedicated tool or answer with evidence already gathered."
				blockedStreak++
			} else {
				blockedStreak = 0
			}
			if verified {
				runFindings++
				nonFindingStreak = 0
			} else {
				nonFindingStreak++
			}

			events <- Event{Type: EvToolDone, Tool: tc.Function.Name, Result: displayResult}
			sanitizedResult := sanitizeToolOutput(llmResult)
			messages = append(messages, openai.ToolMessage(tc.ID, sanitizedResult))
			o.history = append(o.history, openai.ToolMessage(tc.ID, sanitizedResult))
			o.retainHistory()

			if strings.Contains(result, "[HitL_SUSPENDED]") {
				events <- Event{Type: EvStatus, Content: "Agent execution suspended. Awaiting human approval..."}

				// Block on the approval event rather than consuming a CPU core while waiting.
				if err := core.GlobalHitL.Wait(ctx); err != nil {
					if o.actions != nil {
						o.actions.Finish("interrupted", err.Error())
					}
					return err
				}

				// Once answered, inject the answer into the loop context as if the tool returned it
				ans := core.GlobalHitL.ConsumeAnswer()
				messages = append(messages, openai.UserMessage(fmt.Sprintf("Human-in-the-loop response: %s", ans)))
				o.history = append(o.history, openai.UserMessage(fmt.Sprintf("Human-in-the-loop response: %s", ans)))
				o.retainHistory()
				events <- Event{Type: EvStatus, Content: "Approval received. Resuming execution..."}
			}

			if simpleQuery && (tc.Function.Name == "shell_execute" || tc.Function.Name == "nmap") {
				shellCalls++
				if known := extractKnownAnswer(o.recentToolOutputs); known != "" && !answerNudged {
					nudge := fmt.Sprintf("[SYSTEM] You already have the answer: %q appears in the tool output above. The operator asked a one-fact question. Respond NOW with that value and NO further tool calls. Do not run iwconfig/iwgetid/ip/echo variants.", known)
					messages = append(messages, openai.UserMessage(nudge))
					o.history = append(o.history, openai.UserMessage(nudge))
					o.retainHistory()
					answerNudged = true
				} else if shellCalls >= 3 && !answerNudged {
					nudge := "[SYSTEM] You have run 3 tools for a one-fact question. Answer NOW with the best value from the outputs above and NO further tool calls."
					messages = append(messages, openai.UserMessage(nudge))
					o.history = append(o.history, openai.UserMessage(nudge))
					o.retainHistory()
					answerNudged = true
				}
			}
			if blockedStreak >= 2 && !blockedNudged {
				nudge := "[SYSTEM] Two calls were blocked by policy in a row. Stop retrying blocked approaches with different arguments. Use the dedicated tool already suggested, or answer with the evidence gathered so far."
				messages = append(messages, openai.UserMessage(nudge))
				o.history = append(o.history, openai.UserMessage(nudge))
				o.retainHistory()
				blockedNudged = true
			}
			if runFindings > 0 && nonFindingStreak >= 3 && !finalizeNudged {
				nudge := fmt.Sprintf("[SYSTEM] %d tool call(s) since the last new finding; you already banked %d verified finding(s) this run. If that satisfies the operator's request, compose the final answer NOW with no further tool calls. Otherwise state what is still missing and continue.", nonFindingStreak, runFindings)
				messages = append(messages, openai.UserMessage(nudge))
				o.history = append(o.history, openai.UserMessage(nudge))
				o.retainHistory()
				finalizeNudged = true
			}
		}
		o.fastPhaseNext = fastRound
	}

	err = fmt.Errorf("agent hit max iteration limit (%d) — possible infinite loop", maxIter)
	if o.actions != nil {
		o.actions.Finish("failed", err.Error())
	}
	events <- Event{Type: EvError, Content: err.Error()}
	return err
}

// ExecuteChat runs a lightweight no-tools completion for conversational messages.
func (o *Orchestrator) ExecuteChat(ctx context.Context, userMsg string, events chan<- Event) error {
	defer close(events)

	memoryCtx := ""
	if o.graph != nil {
		memoryCtx = o.graph.Snapshot()
	}
	messages := BuildMessages(o.sysPrompt, memoryCtx, o.history, userMsg)

	events <- Event{Type: EvStatus, Content: "Thinking..."}

	// For chat we want streaming — more responsive feel
	finalContent, err := o.provider.StreamFinal(ctx, messages, func(token string) {
		events <- Event{Type: EvToken, Content: token}
	})
	if err != nil {
		events <- Event{Type: EvError, Content: fmt.Sprintf("Chat error: %v", err)}
		return err
	}

	events <- Event{Type: EvDone, Content: finalContent}
	o.history = append(o.history,
		openai.UserMessage(userMsg),
		openai.AssistantMessage(finalContent),
	)
	o.retainHistory()
	return nil
}

// trimForVerification bounds the size of the agent's final claim before it is
// sent to the evidence validator.
func trimForVerification(s string) string {
	if len(s) > 4000 {
		s = s[:4000]
	}
	return s
}

func needsEvidenceReview(final string, recs []toolOutputEvidence) bool {
	if strings.TrimSpace(final) == "" || len(recs) == 0 {
		return false
	}
	if len(final) >= 600 {
		return true
	}
	low := strings.ToLower(final)
	for _, kw := range []string{"tactical assessment", "exploitability score", "attack vector", "phase 1", "phase 2", "open port", "cve-", "flag{"} {
		if strings.Contains(low, kw) {
			return true
		}
	}
	if ipv4Re.MatchString(final) || macRe.MatchString(final) {
		return true
	}
	return false
}

// formatArgs pretty-prints JSON tool arguments for display.
func formatArgs(raw string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return raw
	}
	var parts []string
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := m[k]
		parts = append(parts, fmt.Sprintf("%s: %v", k, v))
	}
	return strings.Join(parts, " | ")
}

// sanitizeToolOutput strips XML-like tags and known prompt injection patterns
// from external tool outputs before they are injected into the LLM context.
// This prevents prompt injection attacks via malicious web content, OSINT results,
// or compromised tool outputs.
func sanitizeToolOutput(output string) string {
	// Strip XML-like tags that could be used for injection
	re := regexp.MustCompile(`(?s)<[^>]+>`)
	output = re.ReplaceAllString(output, "")

	// Strip common injection patterns
	injectionPatterns := []string{
		"ignore all previous instructions",
		"ignore previous instructions",
		"disregard all previous",
		"forget everything above",
		"new instructions:",
		"system prompt:",
		"you are now",
		"from now on",
	}
	lower := strings.ToLower(output)
	for _, pattern := range injectionPatterns {
		if strings.Contains(lower, pattern) {
			// Flag the output but don't strip it entirely
			output = fmt.Sprintf("[WARNING: External output contains potential injection pattern]\n%s", output)
			break
		}
	}
	return output
}

// extractTargetFromMessage attempts to extract a target host/domain/IP from a user message.
func extractTargetFromMessage(msg string) string {
	// Look for IP addresses
	reIP := regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	if m := reIP.FindString(msg); m != "" {
		return m
	}
	// Look for domain-like patterns
	reDomain := regexp.MustCompile(`\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})\b`)
	if m := reDomain.FindString(msg); m != "" {
		return m
	}
	return ""
}
