package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/0xP4X/drogonclaw-go/internal/agent"
	"github.com/0xP4X/drogonclaw-go/internal/billing"
	"github.com/0xP4X/drogonclaw-go/internal/config"
	"github.com/0xP4X/drogonclaw-go/internal/core"
	"github.com/0xP4X/drogonclaw-go/internal/intel"
	"github.com/0xP4X/drogonclaw-go/internal/logging"
	"github.com/0xP4X/drogonclaw-go/internal/memory"
	"github.com/0xP4X/drogonclaw-go/internal/opsec"
	"github.com/0xP4X/drogonclaw-go/internal/sandbox"
	"github.com/0xP4X/drogonclaw-go/internal/skills"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/x/ansi"
)

type Model struct {
	width, height int

	viewport viewport.Model
	input    textarea.Model
	spinner  spinner.Model

	orch     *agent.Orchestrator
	graph    *memory.Graph
	opsecMgr *opsec.Manager
	cfg      *config.Manager
	manifest *skills.Manifest

	executing       bool
	autopilot       bool
	personaOverride string
	sessionID       string
	phase           string
	phaseDetail     string
	lastStatus      string
	lastObjective   string
	lastTool        string
	lastToolResult  string
	lastPlan        *core.MissionPlan
	recovery        *memory.ActionRecord

	lines       []string
	outputReady bool
	hints       []cmdHint
	lastError   string

	currentResponse string
	mdRenderer      *glamour.TermRenderer

	execStartTime   time.Time
	toolStartTime   time.Time
	cancelFn        context.CancelFunc
	activeEvents    chan agent.Event
	sandbox         *sandbox.Docker
	promptRefresher func() string
	selectedHint    int
	bannerShown     bool

	userScrolledUp bool
	history        []string
	historyIdx     int
	historyBuf     string
	pendingConfirm string
	activeToolName string
	activeToolLine int
	ctrlCAt        time.Time
	activeMode     string
	activeChain    *intel.AttackChain
	targetAnalyzer *intel.TargetAnalyzer

	promptQueue         []string
	pendingApprovalTool string
	pendingApprovalEst  string
	tracker             *billing.Tracker

	// Sidebar and timeline
	showSidebar      bool
	showToolDetail   bool
	sessionLog       *logging.SessionTimeline
	lastStreamTime   time.Time
	stepCount        int
	totalSteps       int
	activeToolDetail *ToolDetail

	// New redesign state
	theme      Theme
	layout     tuiLayout
	leader     LeaderState
	modelName  string
	startTime  time.Time
	lastPhase  string
	toolCount  int
	findingCount int
	entityCount  int
	relationCount int
	totalTokens  int
	totalCost    float64
	recentTools      []string
	findings         []string
	lastFindingsIdx  int // tracks how many findings were shown inline on last EvDone
}

type cmdHint struct {
	cmd  string
	desc string
}

// LeaderState holds the state for leader key handling
type LeaderState struct {
	Active    bool
	Timeout   time.Duration
	StartTime time.Time
}

func New(
	orch *agent.Orchestrator,
	g *memory.Graph,
	opsecMgr *opsec.Manager,
	cfg *config.Manager,
	manifest *skills.Manifest,
	sb *sandbox.Docker,
) (*Model, error) {
	sp := spinner.New()
	sp.Spinner = spinner.Line
	sp.Style = SpinnerStyle

	ta := textarea.New()
	ta.Placeholder = "Enter mission objective or /help..."
	ta.Focus()
	ta.SetValue("")
	ta.CharLimit = 4096
	ta.SetHeight(1)
	ta.ShowLineNumbers = false
	ta.KeyMap.InsertNewline.SetEnabled(false)

	vp := viewport.New(120, 30)
	vp.Style = OutputPaneStyle

	mdRenderer, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(120),
	)
	if err != nil {
		return nil, fmt.Errorf("glamour init: %w", err)
	}

	sessionID := orch.SessionID

	// Initialize session logger
	sessionLog, _ := logging.NewSessionLogger(sessionID)

	// Resolve theme from config (defaults to dark) and apply globally so
	// all lipgloss styles match the saved preference on first frame.
	initialTheme := GetTheme(cfg.GetTheme())
	ApplyTheme(initialTheme)
	m := &Model{
		viewport:       vp,
		input:          ta,
		spinner:        sp,
		orch:           orch,
		graph:          g,
		opsecMgr:       opsecMgr,
		cfg:            cfg,
		manifest:       manifest,
		sessionID:      sessionID,
		mdRenderer:     mdRenderer,
		sandbox:        sb,
		historyIdx:     -1,
		activeToolLine: -1,
		phase:          "idle",
		recovery:       orch.Recovery(),
		targetAnalyzer: &intel.TargetAnalyzer{},
		sessionLog:     sessionLog,
		lastStreamTime: time.Now(),
		// New redesign state
		theme: initialTheme,
		leader: LeaderState{
			Timeout: 2 * time.Second,
		},
		startTime:  time.Now(),
		showSidebar: true,
	}

	return m, nil
}

func (m Model) Init() tea.Cmd {
	var cmds []tea.Cmd
	cmds = append(cmds, m.spinner.Tick, textarea.Blink, tea.SetWindowTitle("DrogonClaw"))

	// Show welcome banner if no provider has been configured yet.
	// GetProvider() defaults to "openrouter" so we must check the raw key.
	if m.cfg.GetString("AI_PROVIDER") == "" && m.cfg.GetString("OPENROUTER_API_KEY") == "" && m.cfg.GetString("OPENAI_API_KEY") == "" {
		cmds = append(cmds, func() tea.Msg {
			return WelcomeBannerMsg{Show: true}
		})
	}

	return tea.Batch(cmds...)
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {

	case WelcomeBannerMsg:
		if msg.Show {
			var sb strings.Builder
			sb.WriteString("\n")
			sb.WriteString(SectionHeaderStyle.Render("  ⚡ WELCOME TO DROGONCLAW") + "\n")
			sb.WriteString(SectionRuleStyle.Render("  " + strings.Repeat("─", 60)) + "\n\n")
			sb.WriteString(HintDescStyle.Render("  Configuration required. Run /setup to get started:") + "\n\n")
			sb.WriteString(InfoStyle.Render("  /setup        Launch interactive configuration wizard") + "\n")
			sb.WriteString(InfoStyle.Render("  /help         Show all available commands") + "\n")
			sb.WriteString(InfoStyle.Render("  /config       View current settings") + "\n\n")
			sb.WriteString(WarningStyle.Render("  Tip: You can use DrogonClaw immediately with /setup") + "\n")
			sb.WriteString(SectionRuleStyle.Render("  " + strings.Repeat("─", 60)) + "\n\n")
			m.appendLine(sb.String())
		}
		return m, nil

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.input.SetWidth(max(8, msg.Width-InputPaneStyle.GetHorizontalFrameSize()-8))
		if msg.Width < sidebarMinWidth+20 {
			m.showSidebar = false
		} else {
			m.showSidebar = true
		}
		m.layout = calculateLayoutWithSidebar(m.width, m.height, m.showSidebar)
		m.updateViewportContent()
		if m.mdRenderer != nil {
			m.mdRenderer, _ = glamour.NewTermRenderer(
				glamour.WithAutoStyle(),
				glamour.WithWordWrap(max(1, m.layout.contentWidth-2)),
			)
		}

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			if m.executing && m.cancelFn != nil {
				if time.Since(m.ctrlCAt) < 2*time.Second {
					m.cancelFn()
					m.appendLine(WarningStyle.Render("  [!] Execution halted by user."))
					m.executing = false
					m.activeToolName = ""
					m.ctrlCAt = time.Time{}
					if core.GlobalHitL.HasPending() {
						core.GlobalHitL.Resolve("CANCELLED")
					}
				} else {
					m.ctrlCAt = time.Now()
					m.appendLine(WarningStyle.Render("  [!] Press Ctrl+C again within 2s to abort execution."))
				}
			} else {
				return m, tea.Quit
			}
			return m, nil
		}

		// Ctrl+P command palette — shows all commands for recognition
		if msg.String() == "ctrl+p" {
			m.input.SetValue("/")
			m.hints = matchHints("/")
			m.selectedHint = 0
			return m, nil
		}

		// Ctrl+B toggles sidebar
		if msg.String() == "ctrl+b" {
			if m.showSidebar || m.width >= sidebarMinWidth+20 {
				m.showSidebar = !m.showSidebar
			}
			state := "OFF"
			if m.showSidebar {
				state = "ON"
			}
			m.appendLine(InfoStyle.Render(fmt.Sprintf("  [-] Sidebar %s", state)))
			return m, nil
		}

		// Ctrl+T toggles tool detail panel
		if msg.String() == "ctrl+t" {
			m.showToolDetail = !m.showToolDetail
			return m, nil
		}

		// Direct shortcuts (no leader key needed)
		if msg.String() == "ctrl+a" {
			// Toggle autopilot
			m.autopilot = !m.autopilot
			m.orch.Autopilot = m.autopilot
			state := "MANUAL"
			if m.autopilot {
				state = "AUTOPILOT"
			}
			m.appendLine(WarningStyle.Render(fmt.Sprintf("  [!] Mode: %s", state)))
			return m, nil
		}

		if msg.String() == "ctrl+s" {
			// Show status
			for _, line := range strings.Split(m.renderStatusReport(), "\n") {
				m.appendLine(line)
			}
			return m, nil
		}

		if msg.String() == "ctrl+d" {
			// Show cost
			if m.tracker == nil {
				m.appendLine(WarningStyle.Render("  [!] No token tracker active."))
			} else {
				m.appendLine(m.tracker.Render())
			}
			return m, nil
		}

		// Ctrl+E opens pager (replaces F3)
		if msg.String() == "ctrl+e" {
			cmd, msgStr := m.openViewportInPager()
			if msgStr != "" {
				m.appendLine(msgStr)
			}
			return m, cmd
		}

		// Ctrl+Y copies conversation (replaces F2)
		if msg.String() == "ctrl+y" {
			m.appendLine(m.copyConversation())
			return m, nil
		}

		// Leader key handling
		if msg.String() == "ctrl+x" {
			m.leader.Active = true
			m.leader.StartTime = time.Now()
			return m, nil
		}

		// Handle leader key commands
		if m.leader.Active {
			if time.Since(m.leader.StartTime) > m.leader.Timeout {
				m.leader.Active = false
			} else {
				switch msg.String() {
				case "b":
					if m.showSidebar || m.width >= sidebarMinWidth+20 {
						m.showSidebar = !m.showSidebar
					}
					m.leader.Active = false
					return m, nil
				case "n":
					m.leader.Active = false
					return m, m.newSession()
				case "l":
					m.leader.Active = false
					return m, m.listSessions()
				case "m":
					m.leader.Active = false
					return m, m.listModels()
				case "t":
					m.leader.Active = false
					return m, m.listThemes()
				case "e":
					m.leader.Active = false
					return m, m.openEditor()
				case "x":
					m.leader.Active = false
					return m, m.exportSession()
				case "q":
					m.leader.Active = false
					return m, tea.Quit
				default:
					m.leader.Active = false
				}
			}
		}

		if m.pendingConfirm != "" {
			if msg.Type == tea.KeyEnter {
				answer := strings.TrimSpace(m.input.Value())
				m.input.Reset()
				if m.confirmationAccepted(answer) {
					switch m.pendingConfirm {
					case "new":
						m.orch.NewSession()
						m.graph.Reset()
						m.recovery = nil
						m.appendLine(ToolDoneStyle.Render("  [OK] Session memory cleared. New session started."))
					case "sandbox":
						isSandboxEnabled := m.cfg.IsSandboxEnabled()
						nextEnabled := !isSandboxEnabled
						nextNative := !nextEnabled
						m.cfg.Set("USE_SANDBOX", fmt.Sprintf("%t", nextEnabled))
						m.executing = true
						m.execStartTime = time.Now()
						if nextEnabled {
							m.activeToolName = "docker-sandbox"
							m.appendLine(SpinnerStyle.Render("  [*] Enabling Docker sandbox..."))
						} else {
							m.activeToolName = "native-kali"
							m.appendLine(WarningStyle.Render("  [*] Switching tools to native Kali mode..."))
						}
						m.pendingConfirm = ""
						return m, tea.Batch(m.spinner.Tick, func() tea.Msg {
							ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
							defer cancel()
							if m.sandbox == nil {
								return SandboxToggleResultMsg{Enabled: nextEnabled, Err: fmt.Errorf("runtime manager is unavailable")}
							}
							err := m.sandbox.Initialize(ctx, nextNative)
							if err != nil && nextEnabled {
								_ = m.sandbox.Initialize(ctx, true)
							}
							return SandboxToggleResultMsg{Enabled: nextEnabled, Err: err}
						})
					}
				} else {
					m.appendLine(SessionStyle.Render("  [·] Cancelled."))
				}
				m.pendingConfirm = ""
				return m, nil
			}
			var inputCmd tea.Cmd
			m.input, inputCmd = m.input.Update(msg)
			cmds = append(cmds, inputCmd)
			return m, tea.Batch(cmds...)
		}

		if !m.executing && len(m.hints) > 0 {
			switch msg.Type {
			case tea.KeyUp:
				m.selectedHint--
				if m.selectedHint < 0 {
					m.selectedHint = len(m.hints) - 1
				}
				return m, nil
			case tea.KeyDown:
				m.selectedHint++
				if m.selectedHint >= len(m.hints) {
					m.selectedHint = 0
				}
				return m, nil
			case tea.KeyTab:
				if m.selectedHint >= 0 && m.selectedHint < len(m.hints) {
					m.input.SetValue(m.hints[m.selectedHint].cmd + " ")
					m.input.SetCursor(len(m.input.Value()))
					m.hints = nil
					m.selectedHint = 0
					return m, nil
				}
			}
		}

		if !m.executing && len(m.hints) == 0 {
			if msg.String() == "alt+up" && len(m.history) > 0 {
				if m.historyIdx == -1 {
					m.historyBuf = m.input.Value()
					m.historyIdx = len(m.history) - 1
				} else if m.historyIdx > 0 {
					m.historyIdx--
				}
				m.input.SetValue(m.history[m.historyIdx])
				m.input.SetCursor(len(m.input.Value()))
				return m, nil
			}
			if msg.String() == "alt+down" && m.historyIdx != -1 {
				if m.historyIdx < len(m.history)-1 {
					m.historyIdx++
					m.input.SetValue(m.history[m.historyIdx])
				} else {
					m.historyIdx = -1
					m.input.SetValue(m.historyBuf)
				}
				m.input.SetCursor(len(m.input.Value()))
				return m, nil
			}
		}

		if msg.Type == tea.KeyEnter {
			rawInput := strings.TrimSpace(m.input.Value())
			m.input.Reset()
			m.historyIdx = -1
			m.historyBuf = ""
			if rawInput == "" {
				return m, nil
			}

			if m.executing && core.GlobalHitL.HasPending() {
				switch core.GlobalHitL.PendingKind() {
				case core.ApprovalDuration:
					answer := strings.ToLower(strings.TrimSpace(rawInput))
					tool := m.pendingApprovalTool
					if tool == "" {
						tool = "tool"
					}
					m.appendLine(PromptUserStyle.Render(fmt.Sprintf("  [User] %s", rawInput)))
					if answer == "n" || answer == "no" || answer == "skip" ||
						answer == "cancel" || answer == "deny" || answer == "reject" {
						m.appendLine(WarningStyle.Render(fmt.Sprintf("  [✗] Skipped %s at operator's request.", tool)))
						core.GlobalHitL.Resolve("REJECTED")
					} else {
						m.appendLine(ToolDoneStyle.Render("  [✓] Approved. Resuming execution..."))
						core.GlobalHitL.Resolve("APPROVED")
					}
					m.pendingApprovalTool = ""
					m.pendingApprovalEst = ""
				default:
					m.appendLine(PromptUserStyle.Render(fmt.Sprintf("  [User] %s", rawInput)))
					core.GlobalHitL.Resolve(rawInput)
				}
				return m, nil
			}

			if !m.executing {
				if len(m.history) == 0 || m.history[len(m.history)-1] != rawInput {
					m.history = append(m.history, rawInput)
				}
				return m.handleInput(rawInput)
			}

			// Executing and not awaiting approval: queue the prompt to run
			// automatically once the current task completes.
			m.promptQueue = append(m.promptQueue, rawInput)
			return m, nil
		}

		switch msg.Type {
		case tea.KeyUp:
			m.viewport.LineUp(3)
			m.userScrolledUp = true
			return m, nil
		case tea.KeyDown:
			m.viewport.LineDown(3)
			if m.viewport.AtBottom() {
				m.userScrolledUp = false
			}
			return m, nil
		case tea.KeyPgUp:
			m.viewport.HalfViewUp()
			m.userScrolledUp = true
			return m, nil
		case tea.KeyPgDown:
			m.viewport.HalfViewDown()
			if m.viewport.AtBottom() {
				m.userScrolledUp = false
			}
			return m, nil
		case tea.KeyEnd:
			m.viewport.GotoBottom()
			m.userScrolledUp = false
			return m, nil
		case tea.KeyHome:
			m.viewport.GotoTop()
			m.userScrolledUp = true
			return m, nil
		}

		var inputCmd tea.Cmd
		m.input, inputCmd = m.input.Update(msg)
		cmds = append(cmds, inputCmd)

		if !m.executing && strings.HasPrefix(m.input.Value(), "/") {
			m.hints = matchHints(m.input.Value())
			if m.selectedHint >= len(m.hints) {
				m.selectedHint = 0
			}
		} else {
			m.hints = nil
			m.selectedHint = 0
		}

	case spinner.TickMsg:
		if m.executing {
			var spinCmd tea.Cmd
			m.spinner, spinCmd = m.spinner.Update(msg)
			cmds = append(cmds, spinCmd)
		}

	case AgentEventMsg:
		cmds = append(cmds, m.handleAgentEvent(msg.Event)...)

	case HealthResultMsg:
		m.activeToolName = ""
		m.executing = false
		if m.cancelFn != nil {
			m.cancelFn()
			m.cancelFn = nil
		}
		m.activeEvents = nil
		trimmed := strings.TrimRight(msg.Output, "\n")
		for _, line := range strings.Split(trimmed, "\n") {
			m.appendLine(line)
		}
		cmds = append(cmds, textarea.Blink)

	case SandboxToggleResultMsg:
		m.executing = false
		m.activeToolName = ""
		if msg.Err != nil {
			m.cfg.Set("USE_SANDBOX", fmt.Sprintf("%t", !msg.Enabled))
			m.appendLine(ErrorStyle.Render(fmt.Sprintf("  [x] Runtime switch failed: %v", msg.Err)))
			if !msg.Enabled {
				m.appendLine(WarningStyle.Render("  [!] Still using Docker sandbox mode. Use /health to verify runtime state."))
			} else {
				m.appendLine(WarningStyle.Render("  [!] Still using native Kali mode. Use /health to verify runtime state."))
			}
		} else if msg.Enabled {
			m.appendLine(ToolDoneStyle.Render("  [OK] Docker sandbox enabled. Tools now run inside the Kali container."))
		} else {
			m.appendLine(WarningStyle.Render("  [OK] Native Kali mode enabled. Tools now run directly on this machine."))
		}
		cmds = append(cmds, textarea.Blink)

	case SetupResultMsg:
		m.executing = false
		m.activeToolName = ""
		if msg.Err != nil {
			m.appendLine(ErrorStyle.Render(fmt.Sprintf("  [x] Setup wizard failed: %v", msg.Err)))
		} else {
			m.cfg.Reload()
			m.appendLine(ToolDoneStyle.Render("  [OK] Setup complete. Configuration reloaded."))
		}
		cmds = append(cmds, textarea.Blink)

	case PagerFinishedMsg:
		if msg.Path != "" {
			_ = os.Remove(msg.Path)
		}
		if msg.Err != nil {
			m.appendLine(WarningStyle.Render(fmt.Sprintf("  [~] Pager exited: %v", msg.Err)))
		} else {
			m.appendLine(InfoStyle.Render("  [i] Returned to DrogonClaw."))
		}

	case tea.QuitMsg:
		return m, tea.Quit
	}

	var vpCmd tea.Cmd
	m.viewport, vpCmd = m.viewport.Update(msg)
	m.userScrolledUp = !m.viewport.AtBottom()
	cmds = append(cmds, vpCmd)

	return m, tea.Batch(cmds...)
}

func (m *Model) handleInput(raw string) (*Model, tea.Cmd) {
	op := m.graph.GetOperatorProfile()
	ag := m.graph.GetAgentProfile()
	opName := "Unknown"
	if op != nil {
		opName = op.Name
	}
	agName := "drogonclaw"
	if ag != nil {
		agName = strings.ToLower(ag.Name)
	}
	sid := m.sessionID
	if len(sid) > 18 {
		sid = sid[:18]
	}

	promptLine := PromptGlyphStyle.Render("❯ ") + PromptUserStyle.Render(raw)
	_ = opName
	_ = agName
	// Add a blank line before the prompt for turn separation (skip for very first line)
	if len(m.lines) > 0 {
		m.appendLine("")
	}
	m.appendLine(promptLine)
	m.hints = nil

	if strings.HasPrefix(raw, "/") {
		return m.handleSlashCommand(raw)
	}

	m.lastObjective = raw
	m.phase = "planning"
	m.phaseDetail = "Mission accepted"
	m.lastPlan = nil

	if m.targetAnalyzer != nil && m.activeChain == nil {
		profile := m.targetAnalyzer.Analyze(raw)
		if profile.Class != intel.ClassUnknown && profile.Chain != nil {
			m.activeChain = profile.Chain
			m.activeMode = profile.Chain.Name
			if m.promptRefresher != nil {
				base := m.promptRefresher()
				m.orch.UpdateSystemPrompt(base + profile.ModePromptInjection())
			}
			m.appendLine(SidebarTitleStyle.Render(fmt.Sprintf("  [◈] TARGET: %s  →  MODE: %s  (%.0f%% confidence)",
				profile.Raw, profile.Class.String(), profile.Confidence*100)))
			m.appendLine(SpinnerStyle.Render(fmt.Sprintf("  [⛓] Attack chain activated: %s (%d steps)",
				profile.Chain.Name, len(profile.Chain.Steps))))
		}
	}

	m.executing = true
	m.execStartTime = time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Minute)
	m.cancelFn = cancel

	events := make(chan agent.Event, 32)
	m.activeEvents = events

	var runFn func()
	if agent.IsChatOnly(raw, m.graph, m.opsecMgr) {
		runFn = func() { m.orch.ExecuteChat(ctx, raw, events) }
	} else {
		runFn = func() { m.orch.Execute(ctx, raw, events) }
	}

	go runFn()

	return m, tea.Batch(m.spinner.Tick, waitForEvent(events))
}

func phaseFromStatus(status, fallback string) string {
	s := strings.ToLower(strings.TrimSpace(status))
	switch {
	case strings.Contains(s, "plan"):
		return "planning"
	case strings.Contains(s, "think"):
		return "reasoning"
	case strings.Contains(s, "tool") || strings.Contains(s, "execute") || strings.Contains(s, "running"):
		return "executing"
	case strings.Contains(s, "approve") || strings.Contains(s, "suspend"):
		return "waiting"
	case strings.Contains(s, "compose") || strings.Contains(s, "aggregate") || strings.Contains(s, "verify"):
		return "verifying"
	case strings.Contains(s, "done") || strings.Contains(s, "complete"):
		return "complete"
	case strings.Contains(s, "error") || strings.Contains(s, "fail"):
		return "error"
	default:
		return fallback
	}
}

func summarizeResult(result string, limit int) string {
	cleaned := strings.TrimSpace(result)
	if cleaned == "" {
		return ""
	}
	cleaned = strings.ReplaceAll(cleaned, "\n", " ")
	cleaned = strings.Join(strings.Fields(cleaned), " ")
	cleaned = strings.TrimPrefix(cleaned, "[Sandbox Error] ")
	cleaned = strings.TrimPrefix(cleaned, "[Native Error] ")
	cleaned = strings.TrimPrefix(cleaned, "[Certs Error] ")
	return truncate(cleaned, limit)
}

func (m Model) confirmationAccepted(answer string) bool {
	lower := strings.ToLower(strings.TrimSpace(answer))
	return lower == "yes" || lower == "y" || lower == "ok"
}

func (m Model) confirmationPhrase() string {
	return "(yes/no)"
}

func (m Model) runtimeLabel() string {
	if m.sandbox == nil {
		return "unavailable"
	}
	return m.sandbox.RuntimeLabel()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var PromptRefreshFn func() string

func (m *Model) SetPromptRefresher(fn func() string) {
	m.promptRefresher = fn
}

func (m *Model) SetTracker(t *billing.Tracker) {
	m.tracker = t
}

func (m *Model) eventsCh() <-chan agent.Event {
	if m.activeEvents == nil {
		ch := make(chan agent.Event)
		close(ch)
		return ch
	}
	return m.activeEvents
}

const (
	maxOutputLines   = 5000
	maxLineLength    = 4096
	truncationSuffix = "…"
)

type OutputSeverity int

const (
	SeverityInfo OutputSeverity = iota
	SeveritySuccess
	SeverityWarning
	SeverityError
	SeveritySignal
)

func classifyOutputLine(line string) OutputSeverity {
	trimmed := strings.TrimSpace(strings.ToLower(line))
	if strings.HasPrefix(trimmed, "[error]") || strings.HasPrefix(trimmed, "[x]") {
		return SeverityError
	}
	if strings.HasPrefix(trimmed, "[warn]") || strings.HasPrefix(trimmed, "[!]") {
		return SeverityWarning
	}
	if strings.HasPrefix(trimmed, "[ok]") || strings.HasPrefix(trimmed, "[✓]") || strings.HasPrefix(trimmed, "[+]") {
		return SeveritySuccess
	}
	if strings.HasPrefix(trimmed, "[signal]") || strings.HasPrefix(trimmed, "[→]") {
		return SeveritySignal
	}
	return SeverityInfo
}

func truncateLine(line string) string {
	if ansi.StringWidth(line) <= maxLineLength {
		return line
	}
	return ansi.Truncate(line, maxLineLength, truncationSuffix)
}

func truncateVisible(line string, width int) string {
	if width <= 0 {
		return ""
	}
	if ansi.StringWidth(line) <= width {
		return line
	}
	return ansi.Truncate(line, width, truncationSuffix)
}

func truncateOutput(lines []string) []string {
	if len(lines) <= maxOutputLines {
		return lines
	}
	overflow := len(lines) - maxOutputLines
	return append([]string{fmt.Sprintf("… %d earlier line(s) truncated", overflow)}, lines[overflow:]...)
}

func styledLine(line string) string {
	severity := classifyOutputLine(line)
	switch severity {
	case SeverityError:
		return ErrorStyle.Render(line)
	case SeverityWarning:
		return WarningStyle.Render(line)
	case SeveritySuccess:
		return ToolOutputSuccessStyle.Render(line)
	case SeveritySignal:
		return InfoStyle.Render(line)
	default:
		return ToolOutputStyle.Render(line)
	}
}

func formatToolResult(toolName, output string, duration time.Duration, success bool) string {
	var sb strings.Builder
	status := "✓"
	if !success {
		status = "✗"
	}
	sb.WriteString(fmt.Sprintf("  %s  %s  %s\n", status, toolName, duration.Round(time.Millisecond)))
	for _, line := range strings.Split(output, "\n") {
		line = truncateLine(line)
		sb.WriteString("  " + line + "\n")
	}
	return sb.String()
}

func (m Model) renderSections() string {
	dataDir := "data"
	_ = os.MkdirAll(dataDir, 0755)
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return ErrorStyle.Render(fmt.Sprintf("  [✗] Failed to read sections: %v", err))
	}

	var sections []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "graph_") && strings.HasSuffix(name, ".json") {
			id := strings.TrimSuffix(strings.TrimPrefix(name, "graph_"), ".json")
			info, statErr := entry.Info()
			size := int64(0)
			modified := ""
			if statErr == nil {
				size = info.Size()
				modified = info.ModTime().Format("2006-01-02 15:04")
			}
			marker := "  "
			if id == m.sessionID {
				marker = "▶ "
			}
			sections = append(sections, fmt.Sprintf("%s%s  %s  %d bytes", marker, HeaderInfoStyle.Render(id), modified, size))
		}
	}

	if len(sections) == 0 {
		return HintDescStyle.Render("  No previous sections found.")
	}

	var sb strings.Builder
	sb.WriteString(SectionHeaderStyle.Render("  PREVIOUS SECTIONS:"))
	sb.WriteString("\n")
	for _, s := range sections {
		sb.WriteString(s)
		sb.WriteString("\n")
	}
	sb.WriteString(HintDescStyle.Render("  Use /section <id> to switch"))
	return sb.String()
}

func (m *Model) switchSection(sectionID string) {
	target := strings.TrimSpace(sectionID)
	if target == "" {
		m.appendLine(ErrorStyle.Render("  [✗] Section ID cannot be empty."))
		return
	}

	if target == m.sessionID {
		m.appendLine(WarningStyle.Render("  [!] Already in section " + target))
		return
	}

	newGraph := memory.NewGraph(target)
	newJournal := memory.NewActionJournal(target)
	sysPrompt := agent.BuildSystemPrompt(newGraph, m.opsecMgr, "", m.sandbox.RuntimeLabel())
	newOrch := agent.NewOrchestratorWithJournal(
		m.orch.GetProvider(),
		m.orch.GetTools(),
		sysPrompt,
		target,
		newGraph,
		newJournal,
		m.cfg.GetMaxIterations(),
	)

	m.orch = newOrch
	m.graph = newGraph
	m.sessionID = target
	if m.promptRefresher != nil {
		m.SetPromptRefresher(func() string {
			return agent.BuildSystemPrompt(m.graph, m.opsecMgr, "", m.sandbox.RuntimeLabel())
		})
	}
	m.lines = nil
	m.viewport.SetContent("")
	m.lastTool = ""
	m.activeToolName = ""
	m.phase = "idle"
	m.phaseDetail = ""
	m.lastPlan = nil
	m.lastObjective = ""
	m.bannerShown = false
	m.appendLine(InfoStyle.Render(fmt.Sprintf("  [§] Switched to section %s", target)))
}

// Leader key helper functions
func (m *Model) phaseIcon() string {
	switch m.phase {
	case "idle":
		return "○"
	case "planning":
		return "◎"
	case "reasoning":
		return "◉"
	case "executing":
		return "●"
	case "verifying":
		return "✓"
	case "complete":
		return "✓"
	case "error":
		return "✗"
	case "recovering":
		return "↺"
	default:
		return "○"
	}
}

func (m *Model) newSession() tea.Cmd {
	return func() tea.Msg {
		m.orch.NewSession()
		m.graph.Reset()
		m.recovery = nil
		m.sessionID = m.orch.SessionID
		m.lines = nil
		m.viewport.SetContent("")
		m.lastTool = ""
		m.activeToolName = ""
		m.phase = "idle"
		m.phaseDetail = ""
		m.lastPlan = nil
		m.lastObjective = ""
		m.bannerShown = false
		m.stepCount = 0
		m.totalSteps = 0
		m.toolCount = 0
		m.findingCount = 0
		m.recentTools = nil
		m.findings = nil
		m.lastFindingsIdx = 0
		return nil
	}
}

func (m *Model) listSessions() tea.Cmd {
	return func() tea.Msg {
		// This would open a session list view
		// For now, just show a message
		return nil
	}
}

func (m *Model) listModels() tea.Cmd {
	return func() tea.Msg {
		// This would open a model list view
		// For now, just show a message
		return nil
	}
}

func (m *Model) listThemes() tea.Cmd {
	return func() tea.Msg {
		// This would open a theme list view
		// For now, just show a message
		return nil
	}
}

func (m *Model) openEditor() tea.Cmd {
	return func() tea.Msg {
		// This would open an external editor
		// For now, just show a message
		return nil
	}
}

func (m *Model) exportSession() tea.Cmd {
	return func() tea.Msg {
		// This would export the session
		// For now, just show a message
		return nil
	}
}
