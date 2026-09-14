package tui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/0xP4X/drogonclaw-go/internal/agent"
	"github.com/0xP4X/drogonclaw-go/internal/core"
	"github.com/0xP4X/drogonclaw-go/internal/ctf"
	"github.com/0xP4X/drogonclaw-go/internal/health"
	"github.com/0xP4X/drogonclaw-go/internal/intel"
	tea "github.com/charmbracelet/bubbletea"
)

// ansiRE strips terminal escape sequences so copied output is plain text.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]`)

func stripANSI(s string) string {
	return ansiRE.ReplaceAllString(s, "")
}

// helpfulError shows error + available options + example
func helpfulError(title string, details string, options []string, example string) string {
	var sb strings.Builder
	sb.WriteString(ErrorStyle.Render(fmt.Sprintf("  [✗] %s", title)) + "\n")
	if details != "" {
		sb.WriteString(WarningStyle.Render(fmt.Sprintf("      %s", details)) + "\n")
	}
	if len(options) > 0 {
		sb.WriteString(HintDescStyle.Render("      Available: " + strings.Join(options, ", ")) + "\n")
	}
	if example != "" {
		sb.WriteString(InfoStyle.Render(fmt.Sprintf("      Example: %s", example)) + "\n")
	}
	return sb.String()
}

var needSetup bool

// NeedSetup reports whether the operator requested /setup from inside the TUI.
func NeedSetup() bool { return needSetup }

// Command categories used by the registry and the /help renderer.
const (
	catOperations = "OPERATIONS"
	catControls   = "CONTROLS"
	catSession    = "SESSION"
	catUI         = "UI"
)

// slashCommand is a single entry in the slash-command registry. The first name
// is canonical; the rest are aliases. /help, the command palette, the inline
// hint bar, and the dispatcher all derive from this one table, so a new
// command cannot silently lose its documentation.
type slashCommand struct {
	names    []string
	category string
	desc     string
	args     string // argument hint (e.g. "<target>"); "" when the command takes none
	run      func(m *Model, args string) (*Model, tea.Cmd)
}

func (c slashCommand) canonical() string { return c.names[0] }

func (c slashCommand) matches(name string) bool {
	for _, n := range c.names {
		if n == name {
			return true
		}
	}
	return false
}

// slashCommands is the single source of truth for every in-TUI command. It is
// built in an init() because the /help handler renders via renderHelp, which
// reads this table back — a var-initializer literal would form an
// initialization cycle.
var slashCommands []slashCommand

func init() { slashCommands = buildSlashCommands() }

func buildSlashCommands() []slashCommand {
	var out []slashCommand
	out = append(out, operationsCommands()...)
	out = append(out, controlsCommands()...)
	out = append(out, sessionCommands()...)
	out = append(out, uiCommands()...)
	return out
}

func operationsCommands() []slashCommand {
	return []slashCommand{
		{
			names:    []string{"/workflow", "/mode"},
			category: catOperations,
			desc:     "Select attack workflow",
			args:     "[name|off]",
			run: func(m *Model, args string) (*Model, tea.Cmd) {
				m.handleModeCommand(args)
				return m, nil
			},
		},
		{
			names:    []string{"/analyze"},
			category: catOperations,
			desc:     "Classify a target and determine the attack path",
			args:     "<target>",
			run: func(m *Model, args string) (*Model, tea.Cmd) {
				if args == "" {
					m.appendLine(ErrorStyle.Render("  [✗] Usage: /analyze <target>"))
					return m, nil
				}
				profile := m.targetAnalyzer.Analyze(args)
				m.appendLine(SpinnerStyle.Render(profile.Summarize()))
				if profile.Chain != nil {
					m.appendLine(HintDescStyle.Render(fmt.Sprintf("  Next: activate chain with /mode %s", profile.Chain.Name)))
				}
				return m, nil
			},
		},
		{
			names:    []string{"/skills"},
			category: catOperations,
			desc:     "List and search available execution modules",
			args:     "[query]",
			run: func(m *Model, args string) (*Model, tea.Cmd) {
				m.appendLine(renderSkills(m.manifest, args))
				return m, nil
			},
		},
		{
			names:    []string{"/profile"},
			category: catOperations,
			desc:     "Build a passive intelligence profile",
			args:     "<target>",
			run: func(m *Model, args string) (*Model, tea.Cmd) {
				if args == "" {
					m.appendLine(ErrorStyle.Render("  [✗] Usage: /profile <target-domain-or-ip>"))
					return m, nil
				}
				m2, ctx, events, cmd := m.beginTask(90*time.Second, "planning", "Building target profile", 8)
				go func() {
					defer close(events)
					if err := ctx.Err(); err != nil {
						events <- agent.Event{Type: agent.EvError, Content: "Target profile cancelled: " + err.Error()}
						return
					}
					events <- agent.Event{Type: agent.EvStatus, Content: "Gathering passive intelligence for target..."}
					profile, err := intel.BuildPublicProfile(args, m.cfg.GetShodanAPIKey(), m.cfg.GetVirusTotalAPIKey(), intel.DefaultProfileDependencies())
					if err != nil {
						events <- agent.Event{Type: agent.EvError, Content: fmt.Sprintf("Target profile failed: %v", err)}
						return
					}
					if err := ctx.Err(); err != nil {
						events <- agent.Event{Type: agent.EvError, Content: "Target profile cancelled: " + err.Error()}
						return
					}
					events <- agent.Event{Type: agent.EvDone, Content: intel.FormatPublicProfile(profile)}
				}()
				return m2, cmd
			},
		},
		{
			names:    []string{"/ctf"},
			category: catOperations,
			desc:     "Run local CTF artifact triage",
			args:     "<file-or-dir>",
			run: func(m *Model, args string) (*Model, tea.Cmd) {
				if args == "" {
					m.appendLine(ErrorStyle.Render("  [✗] Usage: /ctf <local-file-or-directory>"))
					return m, nil
				}
				m2, ctx, events, cmd := m.beginTask(2*time.Minute, "planning", "Running CTF triage", 8)
				go func() {
					defer close(events)
					events <- agent.Event{Type: agent.EvStatus, Content: "Running local CTF solver (scan -> decode -> verify)..."}
					rs, err := ctf.Solve(ctx, ctf.LocalTask{Path: args})
					if err != nil {
						events <- agent.Event{Type: agent.EvError, Content: fmt.Sprintf("CTF solve failed: %v", err)}
						return
					}
					events <- agent.Event{Type: agent.EvDone, Content: ctf.FormatSolve(rs)}
				}()
				return m2, cmd
			},
		},
		{
			names:    []string{"/swarm"},
			category: catOperations,
			desc:     "Dispatch a parallel sub-agent swarm",
			args:     "<objective>",
			run: func(m *Model, args string) (*Model, tea.Cmd) {
				if args == "" {
					m.appendLine(ErrorStyle.Render("  [✗] Usage: /swarm <mission objective>"))
					return m, nil
				}
				m2, ctx, events, cmd := m.beginTask(120*time.Minute, "planning", "Swarm commander engaged", 32)
				objective := args
				go func() {
					defer close(events)
					events <- agent.Event{Type: agent.EvStatus, Content: "Dispatching autonomous sub-agent swarm..."}
					sysPrompt := ""
					if m.promptRefresher != nil {
						sysPrompt = m.promptRefresher()
					}
					commander := agent.NewSwarmCommander(m.orch.GetProvider(), m.orch.GetTools(), sysPrompt, m.sessionID, m.graph)
					result, err := commander.ExecuteSwarm(ctx, objective, events)
					if err != nil {
						events <- agent.Event{Type: agent.EvError, Content: fmt.Sprintf("Swarm failed: %v", err)}
					} else {
						events <- agent.Event{Type: agent.EvDone, Content: result}
					}
				}()
				return m2, cmd
			},
		},
	}
}

func controlsCommands() []slashCommand {
	return []slashCommand{
		{
			names:    []string{"/config"},
			category: catControls,
			desc:     "View or modify settings (provider, model, routing, theme, execution)",
			args:     "[set KEY VALUE]",
			run: func(m *Model, args string) (*Model, tea.Cmd) {
				if args == "" {
					// View all settings
					for _, line := range strings.Split(renderConfigSummary(m.cfg), "\n") {
						m.appendLine(line)
					}
					return m, nil
				}
				// /config set KEY VALUE
				parts := strings.SplitN(strings.TrimSpace(args), " ", 3)
				if len(parts) < 3 || strings.ToLower(parts[0]) != "set" {
					m.appendLine(ErrorStyle.Render("  [✗] Usage: /config set KEY VALUE"))
					return m, nil
				}
				key, val := parts[1], parts[2]
				return m.handleConfigSet(key, val)
			},
		},
		{
			names:    []string{"/set"},
			category: catControls,
			desc:     "Quickly set a config value (alias: /config set)",
			args:     "<KEY> <VALUE>",
			run: func(m *Model, args string) (*Model, tea.Cmd) {
				parts := strings.SplitN(strings.TrimSpace(args), " ", 2)
				if len(parts) != 2 {
					m.appendLine(ErrorStyle.Render("  [✗] Usage: /set KEY VALUE"))
					m.appendLine(HintDescStyle.Render("      Example: /set EXECUTION_MODE autonomous"))
					return m, nil
				}
				return m.handleConfigSet(parts[0], parts[1])
			},
		},
		{
			names:    []string{"/router"},
			category: catControls,
			desc:     "Configure intelligent routing (auto|local|9router|off|status)",
			args:     "[auto|local|9router|off|status]",
			run: func(m *Model, args string) (*Model, tea.Cmd) {
				return m.handleRouterCommand(args)
			},
		},
		{
			names:    []string{"/providers"},
			category: catControls,
			desc:     "Show provider health and routing status",
			run: func(m *Model, args string) (*Model, tea.Cmd) {
				return m.handleProvidersCommand(args)
			},
		},
		{
			names:    []string{"/theme"},
			category: catControls,
			desc:     "Switch color theme (dark|light|dracula|nord|gruvbox)",
			args:     "[name]",
			run: func(m *Model, args string) (*Model, tea.Cmd) {
				return m.handleThemeCommand(args)
			},
		},
		{
			names:    []string{"/auto"},
			category: catControls,
			desc:     "Toggle autopilot (auto-accept long-running tools, Ctrl+A)",
			args:     "[on|off]",
			run: func(m *Model, args string) (*Model, tea.Cmd) {
				if strings.TrimSpace(args) == "" {
					state := "off"
					if m.autopilot {
						state = "on"
					}
					m.appendLine(InfoStyle.Render(fmt.Sprintf("  [i] Autopilot: %s — use /auto on/off", state)))
					return m, nil
				}
				return m.handleConfigSet("AUTOPILOT", args)
			},
		},
	}
}

// handleConfigSet handles /set and /config set operations
func (m *Model) handleConfigSet(key, val string) (*Model, tea.Cmd) {
	key = strings.ToUpper(strings.TrimSpace(key))
	val = strings.TrimSpace(val)

	switch key {
	case "AUTOPILOT", "EXECUTION_MODE":
		enabled := strings.ToLower(val) == "on" || strings.ToLower(val) == "true" || strings.ToLower(val) == "autonomous"
		m.autopilot = enabled
		m.orch.Autopilot = enabled
		m.cfg.SetAutopilot(enabled)
		state := "MANUAL"
		if enabled {
			state = "AUTONOMOUS"
		}
		m.appendLine(ToolDoneStyle.Render(fmt.Sprintf("  [✓] Execution Mode: %s", state)))

	case "OPSEC", "EVASION":
		lower := strings.ToLower(val)
		if lower == "high" || lower == "medium" || lower == "low" {
			m.opsecMgr.Toggle()
			m.appendLine(ToolDoneStyle.Render(fmt.Sprintf("  [✓] Evasion Level: %s", lower)))
		} else {
			m.appendLine(ErrorStyle.Render("  [✗] Evasion must be: high, medium, or low"))
			return m, nil
		}

	case "SANDBOX", "ISOLATION":
		enabled := strings.ToLower(val) == "on" || strings.ToLower(val) == "true"
		m.cfg.Set("USE_SANDBOX", map[bool]string{true: "true", false: "false"}[enabled])
		state := "OFF"
		if enabled {
			state = "ON"
		}
		m.appendLine(ToolDoneStyle.Render(fmt.Sprintf("  [✓] Isolation: %s", state)))

	case "THEME":
		return m.handleThemeCommand(val)

	case "AI_PROVIDER", "AI_MODEL", "ROUTER_MODE", "NINEROUTER_API_KEY":
		m.cfg.Set(key, val)
		m.appendLine(ToolDoneStyle.Render(fmt.Sprintf("  [✓] %s set to: %s", key, truncate(val, 40))))

	default:
		m.appendLine(WarningStyle.Render(fmt.Sprintf("  [!] Unknown setting: %s", key)))
		m.appendLine(HintDescStyle.Render("  Available: AUTOPILOT/EXECUTION_MODE, OPSEC/EVASION, SANDBOX/ISOLATION, THEME, AI_PROVIDER, AI_MODEL, ROUTER_MODE, NINEROUTER_API_KEY"))
	}
	return m, nil
}

func sessionCommands() []slashCommand {
	return []slashCommand{
		{
			names:    []string{"/help", "/commands"},
			category: catSession,
			desc:     "Show the complete command reference",
			run: func(m *Model, _ string) (*Model, tea.Cmd) {
				m.appendLine(renderHelp())
				return m, nil
			},
		},
		{
			names:    []string{"/status"},
			category: catSession,
			desc:     "Session metrics: runtime, tools run, findings count, current phase",
			run: func(m *Model, _ string) (*Model, tea.Cmd) {
				for _, line := range strings.Split(m.renderStatusReport(), "\n") {
					m.appendLine(line)
				}
				return m, nil
			},
		},
		{
			names:    []string{"/cost"},
			category: catSession,
			desc:     "Token usage breakdown: input/output tokens, cost, routing savings",
			run: func(m *Model, _ string) (*Model, tea.Cmd) {
				if m.tracker == nil {
					m.appendLine(WarningStyle.Render("  [!] No token tracker active."))
				} else {
					m.appendLine(m.tracker.Render())
				}
				return m, nil
			},
		},
		{
			names:    []string{"/health"},
			category: catSession,
			desc:     "Environment diagnostics: Docker, dependencies, sandbox readiness",
			run: func(m *Model, _ string) (*Model, tea.Cmd) {
				m.appendLine(SpinnerStyle.Render("  [*] Running diagnostic checks..."))
				m.phase = "verifying"
				m.phaseDetail = "Diagnostics"
				m.executing = true
				m.execStartTime = time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
				m.cancelFn = cancel
				m.activeEvents = nil
				healthWidth := m.viewport.Width
				if healthWidth <= 0 {
					healthWidth = m.width - 4
				}
				return m, tea.Batch(m.spinner.Tick, func() tea.Msg {
					return HealthResultMsg{Output: health.RunDiagnosticsWithWidth(ctx, m.sandbox, healthWidth)}
				})
			},
		},
		{
			names:    []string{"/timeline"},
			category: catSession,
			desc:     "Execution log: when each tool ran, duration, results summary",
			run: func(m *Model, _ string) (*Model, tea.Cmd) {
				m.appendLine(m.renderTimeline())
				return m, nil
			},
		},
		{
			names:    []string{"/findings"},
			category: catSession,
			desc:     "Detection summary: vulnerabilities, credentials, flags, interesting info",
			run: func(m *Model, _ string) (*Model, tea.Cmd) {
				return m.handleFindingsSummary()
			},
		},
		{
			names:    []string{"/setup"},
			category: catSession,
			desc:     "Run the interactive configuration wizard",
			run: func(m *Model, _ string) (*Model, tea.Cmd) {
				needSetup = true
				m.appendLine(InfoStyle.Render("  [i] Launching setup wizard — DrogonClaw will restart afterward."))
				return m, tea.Quit
			},
		},
		{
			names:    []string{"/new"},
			category: catSession,
			desc:     "Clear session memory and start fresh",
			run: func(m *Model, _ string) (*Model, tea.Cmd) {
				m.appendLine(WarningStyle.Render("  [!] Clear session? This will delete all findings, credentials, and flags."))
				m.appendLine(InfoStyle.Render("      Type 'yes' to confirm, or 'no' to cancel"))
				m.pendingConfirm = "new"
				return m, nil
			},
		},
		{
			names:    []string{"/resume"},
			category: catSession,
			desc:     "Resume interrupted execution from last checkpoint",
			run: func(m *Model, _ string) (*Model, tea.Cmd) {
				if m.recovery == nil {
					m.appendLine(WarningStyle.Render("  [!] No interrupted mission available."))
					return m, nil
				}
				m.appendLine(InfoStyle.Render(fmt.Sprintf("  [⟳] Resuming: %s", m.recovery.Objective)))
				m.appendLine(HintDescStyle.Render(fmt.Sprintf("      Last checkpoint: %v", m.recovery.UpdatedAt)))
				m.lastObjective = m.recovery.Objective
				m2, ctx, events, cmd := m.beginTask(120*time.Minute, "recovering", "Restoring last durable checkpoint", 32)
				m.appendLine(SpinnerStyle.Render("  [*] Restoring context. Interrupted tool will be verified before retry."))
				m.recovery = nil
				orch := m.orch
				go func() { _ = orch.Resume(ctx, events) }()
				return m2, cmd
			},
		},
		{
			names:    []string{"/copy"},
			category: catSession,
			desc:     "Export transcript to clipboard and file",
			run: func(m *Model, _ string) (*Model, tea.Cmd) {
				m.appendLine(m.copyConversation())
				return m, nil
			},
		},
		{
			names:    []string{"/clear"},
			category: catSession,
			desc:     "Clear visible terminal output",
			run: func(m *Model, _ string) (*Model, tea.Cmd) {
				m.lines = nil
				m.viewport.SetContent("")
				return m, nil
			},
		},
		{
			names:    []string{"/exit", "/quit"},
			category: catSession,
			desc:     "Terminate session gracefully",
			run: func(m *Model, _ string) (*Model, tea.Cmd) {
				return m, tea.Quit
			},
		},
	}
}

// handleFindingsSummary shows a structured, color-coded summary of detected findings
func (m *Model) handleFindingsSummary() (*Model, tea.Cmd) {
	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(SectionHeaderStyle.Render("  🎯 DISCOVERED FINDINGS & LOOT SUMMARY") + "\n")
	sb.WriteString(SectionRuleStyle.Render("  "+strings.Repeat("─", 64)) + "\n\n")

	if len(m.findings) == 0 {
		sb.WriteString(HintDescStyle.Render("  No security findings detected in current session yet.\n"))
		sb.WriteString(HintDescStyle.Render("  Run recon or exploitation tasks (e.g. /analyze target.com) to discover assets.\n\n"))
	} else {
		sb.WriteString(fmt.Sprintf("  Total Session Findings: %d\n\n", len(m.findings)))
		for _, f := range m.findings {
			badge := ToolDoneStyle.Render(" [FINDING] ")
			low := strings.ToLower(f)
			if strings.Contains(low, "flag") || strings.Contains(low, "ctf") {
				badge = StatusOnStyle.Render(" 🚩 FLAG ")
			} else if strings.Contains(low, "cve-") || strings.Contains(low, "vulnerability") || strings.Contains(low, "critical") || strings.Contains(low, "rce") || strings.Contains(low, "sqli") {
				badge = StatusAlertStyle.Render(" ⚡ VULN ")
			} else if strings.Contains(low, "cred") || strings.Contains(low, "password") || strings.Contains(low, "hash") || strings.Contains(low, "user") {
				badge = WarningStyle.Render(" 🔑 CRED ")
			} else if strings.Contains(low, "port") || strings.Contains(low, "service") {
				badge = InfoStyle.Render(" 🔍 ASSET ")
			}
			sb.WriteString(fmt.Sprintf("  %s %s\n", badge, f))
		}
		sb.WriteString("\n")
	}
	m.appendLine(sb.String())
	return m, nil
}

func uiCommands() []slashCommand {
	return []slashCommand{
		{
			names:    []string{"/sidebar"},
			category: catUI,
			desc:     "Toggle the sidebar panel (Ctrl+B)",
			run: func(m *Model, _ string) (*Model, tea.Cmd) {
				if m.showSidebar || m.width >= sidebarMinWidth+20 {
					m.showSidebar = !m.showSidebar
				}
				state := "OFF"
				if m.showSidebar {
					state = "ON"
				}
				m.appendLine(InfoStyle.Render(fmt.Sprintf("  [sidebar] %s", state)))
				return m, nil
			},
		},
		{
			names:    []string{"/details"},
			category: catUI,
			desc:     "Toggle the tool detail panel (Ctrl+T)",
			run: func(m *Model, _ string) (*Model, tea.Cmd) {
				m.showToolDetail = !m.showToolDetail
				state := "OFF"
				if m.showToolDetail {
					state = "ON"
				}
				m.appendLine(InfoStyle.Render(fmt.Sprintf("  [details] %s", state)))
				return m, nil
			},
		},
	}
}

func (m *Model) handleThemeCommand(args string) (*Model, tea.Cmd) {
	name := strings.TrimSpace(strings.ToLower(args))
	if name == "" {
		current := m.cfg.GetTheme()
		var sb strings.Builder
		sb.WriteString(SectionHeaderStyle.Render("  AVAILABLE THEMES") + "\n")
		sb.WriteString(SectionRuleStyle.Render("  " + strings.Repeat("─", 48)) + "\n\n")
		for _, t := range ListThemes() {
			marker := "  "
			style := HintCmdStyle
			if t == current {
				marker = "▶ "
				style = StatusOnStyle
			}
			sb.WriteString(fmt.Sprintf("%s%s  %s\n", marker, style.Render(t), HintDescStyle.Render(themeDescription(t))))
		}
		sb.WriteString("\n" + HintDescStyle.Render("  Usage: /theme <name>  — e.g. /theme dracula") + "\n")
		m.appendLine(sb.String())
		return m, nil
	}
	if _, ok := Themes[normalizeThemeName(name)]; !ok {
		m.appendLine(ErrorStyle.Render(fmt.Sprintf("  [✗] Unknown theme: %s", name)))
		m.appendLine(HintDescStyle.Render(fmt.Sprintf("  Available: %s", strings.Join(ListThemes(), ", "))))
		return m, nil
	}
	theme := GetTheme(name)
	m.theme = theme
	ApplyTheme(theme)
	m.cfg.SetTheme(normalizeThemeName(name))
	m.appendLine(ToolDoneStyle.Render(fmt.Sprintf("  [✓] Theme: %s", normalizeThemeName(name))))
	return m, nil
}

func themeDescription(name string) string {
	switch normalizeThemeName(name) {
	case "dark":
		return "GitHub-inspired dark (default)"
	case "light":
		return "Light theme for daytime"
	case "dracula":
		return "Dracula purple/green"
	case "nord":
		return "Nord arctic blue"
	case "gruvbox":
		return "Gruvbox warm retro"
	default:
		return ""
	}
}

// beginTask sets up the standard async-task machinery used by the long-running
// slash commands: phase/detail labels, executing state, timer, cancel func,
// and an event channel. It returns the mutated model, the cancellable context
// the task goroutine must honor, the event channel it must drive (and close),
// and the batch command that feeds events to the UI loop.
func (m *Model) beginTask(timeout time.Duration, phase, detail string, cap int) (*Model, context.Context, chan agent.Event, tea.Cmd) {
	m.phase = phase
	m.phaseDetail = detail
	m.executing = true
	m.execStartTime = time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	m.cancelFn = cancel
	events := make(chan agent.Event, cap)
	m.activeEvents = events
	return m, ctx, events, tea.Batch(m.spinner.Tick, waitForEvent(events))
}

// handleSlashCommand dispatches a raw slash input through the command registry.
func (m *Model) handleSlashCommand(raw string) (*Model, tea.Cmd) {
	parts := strings.Fields(raw)
	name := strings.ToLower(parts[0])
	if name == "/" {
		m.appendLine(renderHelp())
		return m, nil
	}
	args := ""
	if len(parts) > 1 {
		args = strings.Join(parts[1:], " ")
	}
	for _, c := range slashCommands {
		if c.matches(name) {
			return c.run(m, args)
		}
	}
	suggestions := suggestCommands(name)
	if len(suggestions) > 0 {
		m.appendLine(WarningStyle.Render(fmt.Sprintf("  [?] Unknown command: %s. Did you mean: %s ?", name, strings.Join(suggestions, ", "))))
		m.appendLine(HintDescStyle.Render(fmt.Sprintf("      Type /help for full reference or press Ctrl+P for palette.")))
	} else {
		m.appendLine(WarningStyle.Render(fmt.Sprintf("  [?] Unknown command: %s. Type /help for reference.", name)))
	}
	return m, nil
}

func suggestCommands(input string) []string {
	input = strings.ToLower(input)
	var exactPrefix []string
	for _, c := range slashCommands {
		for _, n := range c.names {
			if strings.HasPrefix(n, input) {
				exactPrefix = append(exactPrefix, n)
			}
		}
	}
	if len(exactPrefix) > 0 {
		if len(exactPrefix) > 3 {
			exactPrefix = exactPrefix[:3]
		}
		return exactPrefix
	}
	var fuzzy []string
	for _, c := range slashCommands {
		for _, n := range c.names {
			if strings.Contains(n, strings.TrimPrefix(input, "/")) {
				fuzzy = append(fuzzy, n)
				break
			}
		}
	}
	if len(fuzzy) > 0 {
		if len(fuzzy) > 3 {
			fuzzy = fuzzy[:3]
		}
		return fuzzy
	}
	deprecatedHints := map[string][]string{
		"/rate":    {"/router", "/set OPSEC high/medium/low"},
		"/stealth": {"/set OPSEC high/medium/low"},
		"/sandbox": {"/set SANDBOX on/off"},
		"/opsec":   {"/set OPSEC high/medium/low"},
		"/auto":    {"/auto on/off"},
		"/c":       {"/copy", "/clear", "/cost"},
	}
	if hints, ok := deprecatedHints[input]; ok {
		return hints
	}
	best := ""
	bestDist := 100
	for _, c := range slashCommands {
		for _, n := range c.names {
			d := levenshtein(input, n)
			if d < bestDist {
				bestDist = d
				best = n
			}
		}
	}
	if bestDist <= 3 && best != "" {
		return []string{best}
	}
	return nil
}

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			curr[j] = min(min(prev[j]+1, curr[j-1]+1), prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func (m *Model) handleModeCommand(args string) {
	switch args {
	case "":
		m.appendLine(SectionHeaderStyle.Render("  AVAILABLE ATTACK METHODOLOGIES:"))
		for _, name := range intel.ListModes() {
			m.appendLine(HintDescStyle.Render(fmt.Sprintf("      /mode %-20s", name)))
		}
		if m.activeMode != "" {
			m.appendLine(StatusOnStyle.Render(fmt.Sprintf("  [✓] Active methodology: %s", m.activeMode)))
		} else {
			m.appendLine(StatusOffStyle.Render("  [○] No methodology active. Type /mode <name> to activate."))
		}
	case "off", "clear", "reset":
		m.activeChain = nil
		m.activeMode = ""
		if m.promptRefresher != nil {
			m.orch.UpdateSystemPrompt(m.promptRefresher())
		}
		m.appendLine(WarningStyle.Render("  [○] Attack methodology cleared."))
	default:
		chain, ok := intel.GetChainByName(args)
		if !ok {
			m.appendLine(ErrorStyle.Render(fmt.Sprintf("  [✗] Unknown methodology: %s. Type /mode to list.", args)))
			return
		}
		m.activeChain = chain
		m.activeMode = chain.Name
		profile := &intel.TargetProfile{Raw: "manual", Class: chain.Class, Chain: chain, Confidence: 1.0}
		if m.promptRefresher != nil {
			base := m.promptRefresher()
			m.orch.UpdateSystemPrompt(base + profile.ModePromptInjection())
		}
		m.appendLine(StatusOnStyle.Render(fmt.Sprintf("  [◈] METHODOLOGY ACTIVATED: %s", chain.Name)))
		m.appendLine(SpinnerStyle.Render(fmt.Sprintf("  [⛓] %d-step execution chain loaded:", len(chain.Steps))))
		for _, step := range chain.Steps {
			m.appendLine(HintDescStyle.Render(fmt.Sprintf("      [%02d] %-18s %s", step.Priority, step.Tool, step.Description)))
		}
	}
}

func currentSessionID() string {
	return ""
}

// copyConversation dumps the on-screen transcript to a file and tries to push it
// to the system clipboard. DrogonClaw runs in the terminal's alternate screen,
// which has no scrollback, so the only reliable way to copy real output is to
// export it. The plain-text file is always written as a fallback.
func (m *Model) copyConversation() string {
	if len(m.lines) == 0 {
		return WarningStyle.Render("  [!] Nothing to copy yet.")
	}

	plain := stripANSI(stripXMLTags(strings.Join(m.lines, "\n")))

	dir, err := core.LootDir()
	if err != nil {
		dir = "."
	}
	path := filepath.Join(dir, "drogonclaw_transcript.txt")
	if werr := os.WriteFile(path, []byte(plain+"\n"), 0600); werr != nil {
		return ErrorStyle.Render(fmt.Sprintf("  [x] Could not write transcript: %v", werr))
	}

	if copyToClipboard(plain) {
		return ToolOutputSuccessStyle.Render(
			fmt.Sprintf("  [✓] Transcript (%d lines) copied to clipboard and saved to %s", len(m.lines), path))
	}
	return InfoStyle.Render(
		fmt.Sprintf("  [i] Transcript (%d lines) saved to %s — open it outside DrogonClaw to copy (clipboard unavailable here).", len(m.lines), path))
}

// PagerFinishedMsg is sent after the external pager process completes.
type PagerFinishedMsg struct {
	Err  error
	Path string
}

// openViewportInPager writes the current viewport content to a temp file and
// opens it in the user's pager using tea.ExecProcess so terminal raw mode
// is safely suspended and restored.
func (m *Model) openViewportInPager() (tea.Cmd, string) {
	content := m.viewport.View()
	if strings.TrimSpace(content) == "" {
		return nil, WarningStyle.Render("  [!] Nothing to view yet.")
	}

	plain := stripANSI(stripXMLTags(content))

	tmpFile, err := os.CreateTemp("", "drogonclaw-output-*.txt")
	if err != nil {
		return nil, ErrorStyle.Render(fmt.Sprintf("  [x] Could not create temp file: %v", err))
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()

	if werr := os.WriteFile(tmpPath, []byte(plain+"\n"), 0600); werr != nil {
		os.Remove(tmpPath)
		return nil, ErrorStyle.Render(fmt.Sprintf("  [x] Could not write output: %v", werr))
	}

	pager := os.Getenv("PAGER")
	if pager == "" {
		pager = "less -R"
	}

	c := exec.Command("sh", "-c", pager+" "+tmpPath)
	return tea.ExecProcess(c, func(err error) tea.Msg {
		return PagerFinishedMsg{Err: err, Path: tmpPath}
	}), ""
}

// copyToClipboard attempts a native clipboard tool (xclip/wl-copy/pbcopy/...).
// It returns false if none is available; the transcript file is the fallback.
func copyToClipboard(text string) bool {
	if runtime.GOOS == "darwin" {
		return runClip("pbcopy", text)
	}
	if runtime.GOOS == "linux" {
		if runClip("wl-copy", text) {
			return true
		}
		if runClip("xclip", text, "-selection", "clipboard") {
			return true
		}
		return runClip("xsel", text, "--clipboard", "--input")
	}
	if runtime.GOOS == "windows" {
		return runClip("clip", text)
	}
	return false
}

func runClip(name string, text string, args ...string) bool {
	path, err := exec.LookPath(name)
	if err != nil {
		return false
	}
	cmd := exec.Command(path, args...)
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run() == nil
}
