package tui

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/0xP4X/drogonclaw-go/internal/agent"
	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
)

type WelcomeBannerMsg struct {
	Show bool
}

func (m *Model) handleAgentEvent(ev agent.Event) []tea.Cmd {
	var cmds []tea.Cmd

	switch ev.Type {
	case agent.EvThinking:
		m.lastStatus = ev.Content
		m.phase = phaseFromStatus(ev.Content, "reasoning")
		m.phaseDetail = ev.Content

	case agent.EvPlan:
		m.lastPlan = ev.Plan
		m.phase = "planning"
		if ev.Plan != nil && len(ev.Plan.Steps) > 0 {
			m.phaseDetail = fmt.Sprintf("plan: %d steps", len(ev.Plan.Steps))
			m.totalSteps = len(ev.Plan.Steps)
		} else {
			m.phaseDetail = "planning"
		}

	case agent.EvStatus:
		m.lastStatus = ev.Content
		m.phase = phaseFromStatus(ev.Content, m.phase)
		m.phaseDetail = ev.Content
		if strings.HasPrefix(ev.Content, "[SUBAGENT:") || strings.HasPrefix(ev.Content, "[PARALLEL]") {
			badge := SubagentBadgeStyle.Render("SUBAGENT")
			txt := SubagentTextStyle.Render(" " + ev.Content)
			m.appendLine(fmt.Sprintf("%s %s", badge, txt))
		}

	case agent.EvApproval:
		est := ev.Content
		if est == "" {
			est = "a while"
		}
		m.pendingApprovalTool = ev.Tool
		m.pendingApprovalEst = est
		m.appendLine(WarningStyle.Render(fmt.Sprintf("  [approval] %s may take ~%s. Type y/n or Enter to run:", ev.Tool, est)))
		m.phase = "waiting"
		m.phaseDetail = fmt.Sprintf("approval: %s", ev.Tool)

	case agent.EvToolStart:
		if m.currentResponse != "" {
			for _, line := range strings.Split(m.renderAgentResponseString(m.currentResponse), "\n") {
				m.lines = append(m.lines, line)
			}
			m.currentResponse = ""
			m.updateViewportContent()
		}

		m.activeToolName = ev.Tool
		m.lastTool = ev.Tool
		m.phase = "executing"
		m.phaseDetail = ev.Tool
		m.toolStartTime = time.Now()
		m.stepCount++

		// Track recent tools for sidebar display (keep last 10)
		m.recentTools = append([]string{ev.Tool}, m.recentTools...)
		if len(m.recentTools) > 10 {
			m.recentTools = m.recentTools[:10]
		}

		// Log to session timeline
		if m.sessionLog != nil {
			m.sessionLog.LogToolStart(ev.Tool, ev.Args, m.stepCount, m.totalSteps)
		}

		// Update tool detail panel
		if m.showToolDetail {
			m.updateToolDetail(ev.Tool, ev.Args, m.toolStartTime)
		}

		m.appendLine(ToolStartStyle.Render(fmt.Sprintf("▶ %s", ev.Tool)))
		if ev.Args != "" {
			m.appendLine(ToolArgsStyle.Render(fmt.Sprintf("  %s", ev.Args)))
		}
		m.activeToolLine = len(m.lines) - 1

	case agent.EvToolDone:
		m.activeToolName = ""
		m.lastToolResult = summarizeResult(ev.Result, 220)
		m.phase = "verifying"
		m.phaseDetail = ev.Tool
		elapsed := time.Since(m.toolStartTime)
		m.toolCount++ // track total tool executions

		isError := strings.Contains(strings.ToLower(ev.Result), "error") ||
			strings.Contains(strings.ToLower(ev.Result), "failed") ||
			strings.Contains(strings.ToLower(ev.Result), "exit status 127")

		// Log to session timeline
		if m.sessionLog != nil {
			m.sessionLog.LogToolComplete(ev.Tool, ev.Result, elapsed.Round(time.Millisecond).String(), !isError)
		}

		// Complete tool detail panel
		if m.showToolDetail {
			m.completeToolDetail(ev.Result, elapsed, !isError)
		}

		// Detect and log findings
		findings := detectFindings(ev.Result, ev.Tool)
		for _, finding := range findings {
			if m.sessionLog != nil {
				m.sessionLog.LogFinding(finding.Type, finding.Description, finding.Source)
			}
			// Accumulate in model so sidebar + /findings command can display them
			m.findings = append(m.findings, fmt.Sprintf("[%s] %s", strings.ToUpper(finding.Type), finding.Description))
			m.findingCount++
		}

		if isError {
			m.appendLine(ToolErrorStyle.Render(fmt.Sprintf("✗ %s (%s)", ev.Tool, elapsed.Round(10*time.Millisecond))))
		} else {
			m.appendLine(ToolDoneStyle.Render(fmt.Sprintf("✓ %s (%s)", ev.Tool, elapsed.Round(10*time.Millisecond))))
		}

		outputLines := sanitizeToolOutputLines(ev.Result)
		if len(outputLines) > 0 {
			for _, line := range outputLines {
				line = strings.TrimLeft(line, " \t")
				styledLine := colorizeOutputLine(truncateLine(stripXMLTags(line)))
				m.appendLine(styledLine)
			}
		}

		m.activeToolLine = -1

	case agent.EvToken:
		m.currentResponse += ev.Content
		// Update viewport in real-time for streaming responses (time-based throttle)
		if time.Since(m.lastStreamTime) >= 100*time.Millisecond {
			m.updateViewportContent()
			m.lastStreamTime = time.Now()
		}

	case agent.EvDone:
		if m.currentResponse != "" {
			for _, line := range strings.Split(m.renderAgentResponseString(m.currentResponse), "\n") {
				m.lines = append(m.lines, line)
			}
			m.currentResponse = ""
		} else if ev.Content != "" {
			for _, line := range strings.Split(m.renderAgentResponseString(ev.Content), "\n") {
				m.lines = append(m.lines, line)
			}
		}
		m.executing = false
		m.phase = "complete"
		m.phaseDetail = summarizeResult(ev.Content, 120)
		m.lastPlan = nil
		m.cancelFn = nil

		// Auto-surface any findings accumulated this turn
		if sessionFindings := m.sessionFindingsSince(m.lastFindingsIdx); len(sessionFindings) > 0 {
			m.appendLine(m.renderInlineFindingsBadges(sessionFindings))
			m.lastFindingsIdx += len(sessionFindings)
		}

		// Subtle turn-end divider for visual clarity
		m.appendLine(DividerStyle.Render("  " + strings.Repeat("·", 56)))

		cmds = append(cmds, textarea.Blink)
		m.updateViewportContent()
		m.processQueue(&cmds)
		return cmds

	case agent.EvError:
		m.activeToolName = ""
		m.activeToolLine = -1
		m.phase = "error"
		m.phaseDetail = ev.Content
		m.lastPlan = nil
		m.appendLine(ErrorStyle.Render(fmt.Sprintf("  [error] %s", ev.Content)))
		m.executing = false
		m.cancelFn = nil
		m.updateViewportContent()
		m.processQueue(&cmds)
		return cmds
	}

	cmds = append(cmds, waitForEvent(m.eventsCh()))
	return cmds
}

// sessionFindingsSince returns the findings added since the given index.
func (m *Model) sessionFindingsSince(fromIdx int) []string {
	if fromIdx >= len(m.findings) {
		return nil
	}
	return m.findings[fromIdx:]
}

// renderInlineFindingsBadges renders a compact one-liner badge strip for new
// findings found during the current agent turn — shown automatically after
// EvDone so the operator sees what was found without running /findings.
func (m *Model) renderInlineFindingsBadges(newFindings []string) string {
	if len(newFindings) == 0 {
		return ""
	}
	var parts []string
	for _, f := range newFindings {
		low := strings.ToLower(f)
		var badge string
		switch {
		case strings.Contains(low, "[flag]") || strings.Contains(low, "flag{") || strings.Contains(low, "ctf{"):
			badge = StatusOnStyle.Render("🚩 FLAG") + " " + HintDescStyle.Render(truncateLine(f))
		case strings.Contains(low, "[vulnerability]") || strings.Contains(low, "cve-") || strings.Contains(low, "rce") || strings.Contains(low, "sqli"):
			badge = StatusAlertStyle.Render("⚡ VULN") + " " + HintDescStyle.Render(truncateLine(f))
		case strings.Contains(low, "[credential]") || strings.Contains(low, "password") || strings.Contains(low, "hash"):
			badge = WarningStyle.Render("🔑 CRED") + " " + HintDescStyle.Render(truncateLine(f))
		default:
			badge = InfoStyle.Render("🔍 FIND") + " " + HintDescStyle.Render(truncateLine(f))
		}
		parts = append(parts, "  "+badge)
	}
	header := SectionHeaderStyle.Render("  ─── Findings Detected ─────────────────────────────")
	return header + "\n" + strings.Join(parts, "\n")
}

// processQueue launches the next queued prompt (if any) once the current task
// finishes, so the operator can stack objectives without waiting around.
func (m *Model) processQueue(cmds *[]tea.Cmd) {
	if len(m.promptQueue) == 0 {
		return
	}
	next := m.promptQueue[0]
	m.promptQueue = m.promptQueue[1:]
	m.appendLine(QueueStyle.Render(fmt.Sprintf("  ▶ Running queued task (%d remaining): %s", len(m.promptQueue), next)))
	mm, cmd := m.handleInput(next)
	*m = *mm
	if cmd != nil {
		*cmds = append(*cmds, cmd)
	}
}

// colorizeOutputLine applies minimal styling so tool output stays readable
// without overwhelming the terminal. Errors and warnings get a color; everything
// else is plain.
func colorizeOutputLine(raw string) string {
	inner := strings.TrimSpace(raw)
	lower := strings.ToLower(inner)
	switch {
	case strings.HasPrefix(lower, "[error]") || strings.HasPrefix(lower, "error:") || strings.Contains(lower, " permission denied") || strings.Contains(lower, " connection refused") || strings.Contains(lower, " command not found") || strings.Contains(lower, "exit status 127"):
		return ErrorStyle.Render(raw)
	case strings.HasPrefix(lower, "[warning]") || strings.HasPrefix(lower, "warning:") || strings.HasPrefix(lower, "[!]"):
		return WarningStyle.Render(raw)
	case strings.HasPrefix(lower, "[+]") || strings.HasPrefix(lower, "[vulnerability]") || strings.HasPrefix(lower, "[flag]") || strings.HasPrefix(lower, "[ok]") || strings.HasPrefix(lower, "[✓]"):
		return ToolOutputSuccessStyle.Render(raw)
	default:
		return ToolOutputStyle.Render(raw)
	}
}

func sanitizeToolOutputLines(result string) []string {
	// Filter raw HTML index pages with font CSS dumps (useless for analysis)
	if strings.Contains(result, "@font-face") && strings.Contains(result, "--mat-sys-") {
		return []string{"[HTML/CSS Web Response — OWASP Juice Shop App Index]"}
	}
	// Filter raw Express 500 stacktrace dumps
	if strings.Contains(result, "Unexpected path:") && strings.Contains(result, "#stacktrace") {
		lines := strings.Split(result, "\n")
		for _, l := range lines {
			if strings.Contains(l, "Error:") {
				return []string{fmt.Sprintf("[HTTP 500 Server Error — %s]", strings.TrimSpace(l))}
			}
		}
		return []string{"[HTTP 500 Server Error — Unexpected path]"}
	}

	lines := strings.Split(result, "\n")
	if len(lines) > 200 {
		truncated := append(lines[:180], fmt.Sprintf("... (%d additional lines hidden)", len(lines)-180))
		return truncated
	}
	return lines
}

func waitForEvent(events <-chan agent.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-events
		if !ok {
			return AgentEventMsg{Event: agent.Event{Type: agent.EvDone}}
		}
		return AgentEventMsg{Event: ev}
	}
}

// Finding represents a detected finding
type Finding struct {
	Type        string
	Description string
	Source      string
}

// Finding patterns
var (
	// Vulnerability patterns
	vulnPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(sql\s*injection|xss|cross.site|csrf|ssrf|xxe|lfi|rfi)`),
		regexp.MustCompile(`(?i)(vulnerability|cve-\d{4}-\d+)`),
		regexp.MustCompile(`(?i)(critical|high|medium|low)\s*(severity|risk|vulnerability)`),
		regexp.MustCompile(`(?i)(exploitable|exploit)`),
	}

	// Credential patterns
	credPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*\S+`),
		regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+`),
		regexp.MustCompile(`(?i)(token|secret)\s*[:=]\s*\S+`),
		regexp.MustCompile(`(?i)(admin|root)\s*[:=]\s*\S+`),
		regexp.MustCompile(`(?i)(credential|login)\s*(found|discovered|extracted)`),
	}

	// Flag patterns
	flagPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(flag|ctf|htb|picoctf)\{[^\}]+\}`),
		regexp.MustCompile(`(?i)flag\s*[:=]\s*\S+`),
	}

	// Info patterns
	infoPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(port|service|version)\s+\d+`),
		regexp.MustCompile(`(?i)(open|closed|filtered)\s+port`),
		regexp.MustCompile(`(?i)(host|target)\s+(up|down|reachable)`),
	}
)

// detectFindings detects findings in tool output. At most one finding per category
// is emitted so overlapping patterns (e.g. "SQL injection vulnerability") do not
// produce duplicate counts. Deduplication is by category.
func detectFindings(output, tool string) []Finding {
	var findings []Finding

	// Vulnerability: first matching pattern wins
	for _, pattern := range vulnPatterns {
		if matches := pattern.FindStringSubmatch(output); matches != nil {
			findings = append(findings, Finding{
				Type:        "vulnerability",
				Description: matches[0],
				Source:      tool,
			})
			break
		}
	}

	// Credential: first matching pattern wins (redacted)
	for _, pattern := range credPatterns {
		if matches := pattern.FindStringSubmatch(output); matches != nil {
			desc := redactCredential(matches[0])
			findings = append(findings, Finding{
				Type:        "credential",
				Description: desc,
				Source:      tool,
			})
			break
		}
	}

	// Flag: first matching pattern wins
	for _, pattern := range flagPatterns {
		if matches := pattern.FindStringSubmatch(output); matches != nil {
			findings = append(findings, Finding{
				Type:        "flag",
				Description: matches[0],
				Source:      tool,
			})
			break
		}
	}

	// Info: first matching pattern wins
	for _, pattern := range infoPatterns {
		if matches := pattern.FindStringSubmatch(output); matches != nil {
			findings = append(findings, Finding{
				Type:        "info",
				Description: matches[0],
				Source:      tool,
			})
			break
		}
	}

	return findings
}

var credRedactRE = regexp.MustCompile(`(?i)(password|passwd|pwd|api[_-]?key|apikey|token|secret)\s*[:=]\s*(\S+)`)

// redactCredential redacts sensitive parts of credentials
func redactCredential(s string) string {
	return credRedactRE.ReplaceAllString(s, "${1}=[REDACTED]")
}
