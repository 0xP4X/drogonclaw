package tui

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/0xP4X/drogonclaw-go/internal/core"
	"github.com/0xP4X/drogonclaw-go/internal/skills"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

func (m *Model) View() string {
	if m.width == 0 {
		splash := m.renderSplash()
		return splash
	}

	m.layout = calculateLayoutWithSidebar(m.width, m.height, m.showSidebar)

	// Build each zone to exact pixel widths
	header := m.renderHeaderBar()
	content := m.renderContentArea()
	statusBar := m.renderStatusBarBar()
	inputArea := m.renderInputBar()

	// Horizontal rule with proper background
	hline := func() string {
		return lipgloss.NewStyle().
			Foreground(m.theme.Border).
			Background(m.theme.Background).
			Width(m.width).
			Render(strings.Repeat("─", m.width))
	}

	var sb strings.Builder
	sb.WriteString(header)
	sb.WriteString("\n")
	sb.WriteString(hline())
	sb.WriteString("\n")

	if m.showSidebar && m.layout.sidebarWidth > 0 {
		sidebar := m.renderSidebar(m.layout.sidebarWidth, m.layout.sidebarHeight)
		fixedContent := lipgloss.NewStyle().
			Width(m.layout.mainWidth).
			Height(m.layout.contentHeight).
			Render(content)
		sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, fixedContent, sidebar))
	} else {
		sb.WriteString(content)
	}

	sb.WriteString(hline())
	sb.WriteString("\n")
	sb.WriteString(statusBar)
	sb.WriteString("\n")
	sb.WriteString(hline())
	sb.WriteString("\n")
	sb.WriteString(inputArea)

	return sb.String()
}

func (m *Model) renderHeaderBar() string {
	inner := m.renderHeaderLine()
	return lipgloss.NewStyle().
		Background(m.theme.BackgroundSurface).
		Foreground(m.theme.Text).
		Width(m.width).
		Padding(0, 1).
		Render(inner)
}

func (m *Model) renderStatusBarBar() string {
	inner := m.renderStatusBar()
	return lipgloss.NewStyle().
		Background(m.theme.BackgroundSurface).
		Foreground(m.theme.Text).
		Width(m.width).
		Padding(0, 1).
		Render(inner)
}

func (m *Model) renderInputBar() string {
	inner := m.renderInputArea()
	if len(m.promptQueue) == 0 {
		return lipgloss.NewStyle().
			Background(m.theme.BackgroundSurface).
			Foreground(m.theme.Text).
			Width(m.width).
			Padding(0, 1).
			Render(inner)
	}
	qItems := make([]string, 0, len(m.promptQueue))
	for i, q := range m.promptQueue {
		if i >= 2 {
			if len(m.promptQueue) > 3 {
				qItems = append(qItems, fmt.Sprintf("+%d more", len(m.promptQueue)-3))
			}
			break
		}
		qItems = append(qItems, truncate(q, 25))
	}
	queueLine := QueueStyle.Render(fmt.Sprintf("⏳ %d queued: %s", len(m.promptQueue), strings.Join(qItems, " · ")))
	combined := queueLine + "\n" + inner
	return lipgloss.NewStyle().
		Background(m.theme.BackgroundSurface).
		Foreground(m.theme.Text).
		Width(m.width).
		Padding(0, 1).
		Render(combined)
}

func (m Model) renderHeaderLine() string {
	var parts []string

	brandStyle := lipgloss.NewStyle().
		Foreground(m.theme.Primary).
		Bold(true)
	parts = append(parts, brandStyle.Render("DrogonClaw"))

	sep := lipgloss.NewStyle().Foreground(m.theme.BorderSubtle)

	op := m.graph.GetOperatorProfile()
	ag := m.graph.GetAgentProfile()
	if op != nil && ag != nil && m.width >= 50 {
		idStyle := lipgloss.NewStyle().Foreground(m.theme.TextDim)
		parts = append(parts, sep.Render(" │ "))
		parts = append(parts, idStyle.Render(fmt.Sprintf("%s@%s", op.Name, ag.Name)))
	}

	if m.modelName != "" && m.width >= 70 {
		modelStyle := lipgloss.NewStyle().Foreground(m.theme.TextMuted)
		parts = append(parts, sep.Render(" │ "))
		parts = append(parts, modelStyle.Render(m.modelName))
	}

	phaseIcon := m.phaseIcon()
	_, phaseStyle := renderPhaseBadge(m.phase)
	parts = append(parts, sep.Render(" │ "))
	parts = append(parts, phaseStyle.Render(phaseIcon))

	if m.toolCount > 0 && m.width >= 55 {
		countStyle := lipgloss.NewStyle().Foreground(m.theme.TextDim)
		parts = append(parts, sep.Render(" │ "))
		parts = append(parts, countStyle.Render(fmt.Sprintf("%d tools", m.toolCount)))
	}

	return lipgloss.JoinHorizontal(lipgloss.Center, parts...)
}

func (m Model) renderExecutingLine() string {
	tool := m.activeToolName
	if tool == "" {
		tool = m.lastTool
	}

	elapsed := ""
	if !m.execStartTime.IsZero() {
		elapsed = time.Since(m.execStartTime).Round(time.Second).String()
	}

	phase := m.phase
	if phase == "" {
		phase = "executing"
	}
	_, phaseStyle := renderPhaseBadge(phase)

	sep := lipgloss.NewStyle().Foreground(m.theme.BorderSubtle).Render(" │ ")
	var parts []string
	parts = append(parts, m.spinner.View())
	parts = append(parts, phaseStyle.Render(strings.ToUpper(phase)))

	if elapsed != "" {
		parts = append(parts, sep)
		parts = append(parts, lipgloss.NewStyle().Foreground(m.theme.TextDim).Render(elapsed))
	}

	if m.stepCount > 0 {
		stepStyle := lipgloss.NewStyle().Foreground(m.theme.TextDim)
		parts = append(parts, sep)
		parts = append(parts, stepStyle.Render(fmt.Sprintf("step %d/%d", m.stepCount, m.totalSteps)))
	}

	if tool != "" {
		toolStyle := lipgloss.NewStyle().Foreground(m.theme.Accent)
		parts = append(parts, sep)
		parts = append(parts, toolStyle.Render(truncateVisible(tool, max(8, m.width/4))))
	}

	line := lipgloss.JoinHorizontal(lipgloss.Center, parts...)

	if lipgloss.Width(line) > m.width {
		line = m.spinner.View() + " " + phaseStyle.Render(strings.ToUpper(phase))
	}

	return lipgloss.NewStyle().
		Foreground(m.theme.Text).
		Width(m.width).
		Render(line)
}

func (m *Model) renderContentArea() string {
	m.viewport.Width = m.layout.contentWidth
	m.viewport.Height = m.layout.contentHeight

	var base string

	if vpBase := m.viewport.View(); vpBase != "" {
		base = vpBase
	} else {
		m.bannerShown = true
		base = m.renderWelcome()
	}

	if len(m.hints) > 0 {
		base += "\n" + m.renderHints()
	}

	return lipgloss.NewStyle().
		Width(m.layout.mainWidth).
		Height(m.layout.contentHeight).
		Render(base)
}

func (m *Model) renderStatusBar() string {
	var parts []string

	if m.executing {
		anim := m.renderExecutingLine()
		if anim != "" {
			return anim
		}
	}

	modeColor := m.theme.TextDim
	modeIcon := "○"
	if m.autopilot {
		modeColor = m.theme.Warning
		modeIcon = "●"
	}
	modeLabel := lipgloss.NewStyle().Foreground(modeColor).Bold(true).Render(fmt.Sprintf("%s %s", modeIcon, "AUTO"))
	parts = append(parts, modeLabel)

	sep := lipgloss.NewStyle().Foreground(m.theme.BorderSubtle).Render(" │ ")
	parts = append(parts, sep)

	phaseLabel := lipgloss.NewStyle().Foreground(m.theme.TextMuted).Render(strings.ToUpper(m.phase))
	parts = append(parts, phaseLabel)

	if m.stepCount > 0 && m.width >= 50 {
		parts = append(parts, sep)
		stepLabel := lipgloss.NewStyle().Foreground(m.theme.TextDim).Render(fmt.Sprintf("step %d/%d", m.stepCount, m.totalSteps))
		parts = append(parts, stepLabel)
	}

	if m.width >= 60 {
		rightParts := []string{}
		keyStyle := lipgloss.NewStyle().Foreground(m.theme.TextDim)
		rightParts = append(rightParts, keyStyle.Render("Ctrl+P cmds"))
		rightParts = append(rightParts, keyStyle.Render("Ctrl+A auto"))
		rightParts = append(rightParts, keyStyle.Render("Ctrl+B sidebar"))
		if !m.executing {
			rightParts = append(rightParts, keyStyle.Render("/help"))
		}
		rightAligned := lipgloss.JoinHorizontal(lipgloss.Right, rightParts...)
		parts = append(parts, sep)
		parts = append(parts, rightAligned)
	}

	return lipgloss.JoinHorizontal(lipgloss.Center, parts...)
}

func (m *Model) renderInputArea() string {
	// Manage textarea dimensions
	agName := "drogonclaw"
	glyph, _ := m.promptGlyph(agName)
	taWidth := max(1, m.width-lipgloss.Width(glyph)-1)
	m.input.SetWidth(taWidth)

	text := m.input.Value()
	if text == "" {
		m.input.SetHeight(1)
	} else {
		lines := strings.Split(text, "\n")
		totalLines := 0
		for _, line := range lines {
			runeCount := utf8.RuneCountInString(line)
			if runeCount == 0 {
				totalLines++
			} else {
				totalLines += (runeCount + taWidth - 1) / taWidth
			}
		}
		m.input.SetHeight(clamp(totalLines, 1, 6))
	}

	promptStyle := lipgloss.NewStyle().
		Foreground(m.theme.Primary).
		Bold(true)
	prompt := promptStyle.Render("drogonclaw > ")

	return prompt + m.input.View()
}

func (m Model) renderInputLine() string {
	agName := "drogonclaw"
	glyph, _ := m.promptGlyph(agName)

	taWidth := max(1, m.width-lipgloss.Width(glyph)-1)
	m.input.SetWidth(taWidth)

	text := m.input.Value()
	if text == "" {
		m.input.SetHeight(1)
	} else {
		lines := strings.Split(text, "\n")
		totalLines := 0
		for _, line := range lines {
			runeCount := utf8.RuneCountInString(line)
			if runeCount == 0 {
				totalLines++
			} else {
				totalLines += (runeCount + taWidth - 1) / taWidth
			}
		}
		m.input.SetHeight(clamp(totalLines, 1, 6))
	}

	var lines []string

	// Show keyboard shortcuts when input is empty
	if text == "" && len(m.hints) == 0 {
		shortcuts := []string{
			HintDescStyle.Render("  [?] help  "),
			HintDescStyle.Render("[Ctrl+P] palette  "),
			HintDescStyle.Render("[Ctrl+B] sidebar  "),
			HintDescStyle.Render("[Ctrl+S] status"),
		}
		lines = append(lines, strings.Join(shortcuts, ""))
	}

	for i, h := range m.hints {
		prefix := " "
		cmdStr := HintCmdStyle.Render(h.cmd)
		if i == m.selectedHint {
			prefix = "▸ "
			cmdStr = HintSelectedStyle.Render(h.cmd)
		}
		lines = append(lines, prefix+cmdStr+HintDescStyle.Render("  "+truncateVisible(h.desc, max(12, m.width-20))))
	}

	if len(m.promptQueue) > 0 {
		qItems := make([]string, 0, len(m.promptQueue))
		for i, q := range m.promptQueue {
			if i >= 2 {
				if len(m.promptQueue) > 3 {
					qItems = append(qItems, fmt.Sprintf("+%d more", len(m.promptQueue)-3))
				}
				break
			}
			qItems = append(qItems, truncate(q, 25))
		}
		lines = append(lines, QueueStyle.Render(fmt.Sprintf("⏳ %d queued: %s", len(m.promptQueue), strings.Join(qItems, " · "))))
	}

	if m.pendingConfirm != "" {
		lines = append(lines, WarningStyle.Render("Action requires exact confirmation: type "+m.confirmationPhrase()+" or Enter to cancel."))
	}

	lines = append(lines, glyph+m.input.View())
	return InputPaneStyle.Render(strings.Join(lines, "\n"))
}

func (m Model) renderWelcome() string {
	var sb strings.Builder
	width := max(28, m.viewport.Width)
	if width <= 0 {
		width = max(28, m.width)
	}

	provider := fallback(m.cfg.GetProvider(), "provider")
	model := fallback(m.cfg.GetModel(), "model")
	runtime := m.sandbox.RuntimeLabel()
	mode := m.activeMode
	if mode == "" {
		mode = "default"
	}

	sb.WriteString("\n")

	sep := lipgloss.NewStyle().Foreground(m.theme.Border).Render(strings.Repeat("─", min(width-4, 52)))
	sb.WriteString(sep)
	sb.WriteString("\n\n")

	infoItems := []string{
		fmt.Sprintf("  %-10s  %s", lipgloss.NewStyle().Foreground(m.theme.TextMuted).Render("Runtime"), lipgloss.NewStyle().Foreground(m.theme.Text).Render(runtime)),
		fmt.Sprintf("  %-10s  %s", lipgloss.NewStyle().Foreground(m.theme.TextMuted).Render("Engine"), lipgloss.NewStyle().Foreground(m.theme.Text).Render(truncate(provider+"/"+model, max(10, width/2)))),
		fmt.Sprintf("  %-10s  %s", lipgloss.NewStyle().Foreground(m.theme.TextMuted).Render("Mode"), lipgloss.NewStyle().Foreground(m.theme.Text).Render(mode)),
	}
	sb.WriteString(strings.Join(infoItems, "\n"))
	sb.WriteString("\n\n")
	sb.WriteString(sep)
	sb.WriteString("\n\n")

	sb.WriteString(WelcomeHintStyle.Render("  Enter a mission objective to begin, or try a quick command:"))
	sb.WriteString("\n\n")

	commands := []struct{ cmd, desc string }{
		{"/health", "Verify runtime & dependencies"},
		{"/profile", "Build passive target profile"},
		{"/mode", "Select workflow methodology"},
		{"/skills", "Browse available attack modules"},
		{"/status", "Show session metrics"},
		{"/help", "Show all available commands"},
	}

	for _, c := range commands {
		cmdStr := lipgloss.NewStyle().Foreground(m.theme.Primary).Bold(true).Render(fmt.Sprintf("  %-12s", c.cmd))
		descStr := lipgloss.NewStyle().Foreground(m.theme.TextMuted).Render(c.desc)
		sb.WriteString(cmdStr + descStr + "\n")
	}

	return sb.String()
}

func (m Model) viewportDimensions() (width, height int) {
	layout := calculateLayoutWithSidebar(m.width, m.height, m.showSidebar)

	vpWidth := max(8, layout.contentWidth)
	vpHeight := max(3, layout.contentHeight)
	return vpWidth, vpHeight
}

func (m Model) renderSidebar(width, height int) string {
	if width <= 0 {
		return ""
	}

	innerWidth := max(8, width-sidebarPadX*2-2)
	// Reserve 2 lines for padding, clip content to height so sidebar never
	// grows past the main pane (scales with terminal).
	maxLines := max(8, height-2)

	var sb strings.Builder
	lineCount := 0
	addLine := func(s string) bool {
		if lineCount >= maxLines {
			return false
		}
		sb.WriteString(s + "\n")
		lineCount++
		return true
	}

	row := func(label, value string) bool {
		if lineCount >= maxLines {
			return false
		}
		valueWidth := max(4, innerWidth-14)
		labelStyled := lipgloss.NewStyle().Foreground(m.theme.TextDim).Render(fmt.Sprintf("%-10s", label))
		valueStyled := truncateVisible(value, valueWidth)
		return addLine(fmt.Sprintf(" %s %s", labelStyled, valueStyled))
	}

	section := func(title string) bool {
		if lineCount+2 > maxLines {
			return false
		}
		if sb.Len() > 0 {
			if !addLine("") {
				return false
			}
		}
		titleStyled := lipgloss.NewStyle().Foreground(m.theme.TextMuted).Bold(true).Render(title)
		ruleStyle := lipgloss.NewStyle().Foreground(m.theme.BorderSubtle)
		addLine(titleStyled)
		addLine(ruleStyle.Render(strings.Repeat("─", max(4, innerWidth-1))))
		return true
	}

	// SESSION — minimal: session, model, phase only
	section("SESSION")
	provider := fallback(m.cfg.GetProvider(), "none")
	model := fallback(m.cfg.GetModel(), "none")
	_ = row("Session", HeaderInfoStyle.Render(truncateVisible(m.sessionID, max(4, innerWidth-14))))
	_ = row("Model", SidebarValueStyle.Render(truncate(provider+"/"+model, max(1, innerWidth-14))))
	_ = row("Phase", renderSidebarPhase(m.phase))
	if m.activeMode != "" && m.activeMode != "default" {
		_ = row("Attack", SidebarValueStyle.Render(truncate(m.activeMode, max(1, innerWidth-14))))
	}

	// STATS — compact single section
	if m.toolCount > 0 || m.findingCount > 0 || m.stepCount > 0 {
		if section("STATS") {
			if m.toolCount > 0 {
				_ = row("Tools", SidebarValueStyle.Render(fmt.Sprintf("%d", m.toolCount)))
			}
			if m.findingCount > 0 {
				_ = row("Findings", StatusAlertStyle.Render(fmt.Sprintf("%d", m.findingCount)))
			}
		}
	}

	// COST — single compact line instead of 4 rows
	if m.tracker != nil {
		total := m.tracker.Total()
		if total.TotalTokens > 0 {
			if section("COST") {
				cost := m.tracker.TotalCost()
				// e.g. "1.2k tokens · $0.0034"
				tokStr := fmt.Sprintf("%d", total.TotalTokens)
				if total.TotalTokens >= 1000 {
					tokStr = fmt.Sprintf("%.1fk", float64(total.TotalTokens)/1000)
				}
				_ = row("Tokens", SidebarValueStyle.Render(fmt.Sprintf("%s · $%.4f", tokStr, cost)))
			}
		}
	}

	// TOOLS — last 3 only, not 5; overflow hint
	if len(m.recentTools) > 0 && lineCount+2 < maxLines {
		if section("TOOLS") {
			limit := min(3, len(m.recentTools))
			limit = min(limit, maxLines-lineCount-1)
			for i := 0; i < limit; i++ {
				tool := m.recentTools[i]
				toolStyle := lipgloss.NewStyle().Foreground(m.theme.Accent)
				_ = addLine(" " + toolStyle.Render("▶") + " " + truncate(tool, max(1, innerWidth-6)))
			}
			if len(m.recentTools) > limit {
				_ = addLine(" " + lipgloss.NewStyle().Foreground(m.theme.TextDim).Render(fmt.Sprintf("… +%d more", len(m.recentTools)-limit)))
			}
		}
	}

	// FINDINGS — last 3 only
	if len(m.findings) > 0 && lineCount+2 < maxLines {
		if section("FINDINGS") {
			limit := min(3, len(m.findings))
			limit = min(limit, maxLines-lineCount-1)
			for i := 0; i < limit; i++ {
				finding := m.findings[i]
				var findingStyle lipgloss.Style
				low := strings.ToLower(finding)
				switch {
				case strings.Contains(low, "critical") || strings.Contains(low, "high"):
					findingStyle = lipgloss.NewStyle().Foreground(m.theme.Error)
				case strings.Contains(low, "medium") || strings.Contains(low, "warning"):
					findingStyle = lipgloss.NewStyle().Foreground(m.theme.Warning)
				default:
					findingStyle = lipgloss.NewStyle().Foreground(m.theme.Success)
				}
				_ = addLine(" " + findingStyle.Render("●") + " " + truncate(finding, max(1, innerWidth-6)))
			}
			if len(m.findings) > limit {
				_ = addLine(" " + lipgloss.NewStyle().Foreground(m.theme.TextDim).Render(fmt.Sprintf("… +%d more", len(m.findings)-limit)))
			}
		}
	}

	content := strings.TrimSuffix(sb.String(), "\n")

	return lipgloss.NewStyle().
		Background(m.theme.BackgroundPanel).
		Width(width).
		Height(height).
		Padding(1, sidebarPadX, 0, sidebarPadX).
		Render(content)
}

func (m Model) renderStatusReport() string {
	heading := SectionHeaderStyle.Render
	label := SidebarLabelStyle.Render
	value := SidebarValueStyle.Render
	rule := SectionRuleStyle.Render("  " + strings.Repeat("─", max(20, m.viewport.Width-4)))

	onOff := func(on bool, yes string) string {
		if on {
			return StatusOnStyle.Render("● " + yes)
		}
		return StatusOffStyle.Render("○ OFF")
	}
	row := func(key, val string) string {
		return fmt.Sprintf("  %-16s %s", label(key), val)
	}

	phase, _ := renderPhaseBadge(m.phase)
	mode := m.activeMode
	if mode == "" {
		mode = "default"
	}
	elapsed := "idle"
	if !m.execStartTime.IsZero() && m.executing {
		elapsed = time.Since(m.execStartTime).Round(time.Second).String()
	}
	tool := m.activeToolName
	if tool == "" {
		tool = m.lastTool
	}
	if tool == "" {
		tool = "none"
	}
	telegramReady := m.cfg.GetString("TELEGRAM_TOKEN") != "" && m.cfg.GetString("TELEGRAM_CHAT_ID") != ""

	var sb strings.Builder
	sb.WriteString("\n  " + HeaderBrandStyle.Render("WORKSPACE STATUS REPORT") + "\n")
	sb.WriteString(rule + "\n\n")
	sb.WriteString("  " + heading("SESSION CONTEXT") + "\n")
	sb.WriteString(row("Section", value(m.sessionID)) + "\n")
	sb.WriteString(row("Active Phase", phase) + "\n")
	sb.WriteString(row("Workflow", value(mode)) + "\n")
	sb.WriteString(row("Elapsed Time", value(elapsed)) + "\n")
	sb.WriteString(row("Current Tool", value(tool)) + "\n\n")
	sb.WriteString("  " + heading("OPERATIONAL CONTROLS") + "\n")
	sb.WriteString(row("Rate Limit", onOff(m.opsecMgr.IsActive(), "ACTIVE")) + "\n")
	sb.WriteString(row("Auto-run", onOff(m.autopilot, "ENABLED")) + "\n\n")
	sb.WriteString("  " + heading("ENVIRONMENT") + "\n")
	sb.WriteString(row("Execution Engine", value(m.sandbox.RuntimeLabel())) + "\n")
	sb.WriteString(row("Telegram Gateway", onOff(telegramReady, "READY")) + "\n\n")
	sb.WriteString("  " + heading("PENTEST STATS") + "\n")
	sb.WriteString(row("Tools Run", StatusNodeStyle.Render(fmt.Sprintf("%d", m.toolCount))) + "\n")
	sb.WriteString(row("Steps Taken", value(fmt.Sprintf("%d", m.stepCount))) + "\n")
	if m.findingCount > 0 {
		sb.WriteString(row("Findings", StatusAlertStyle.Render(fmt.Sprintf("%d new", m.findingCount))) + "\n")
	}
	sb.WriteString(rule + "\n")

	return sb.String()
}

func (m Model) promptGlyph(agName string) (string, int) {
	switch {
	case m.pendingConfirm != "":
		g := WarningStyle.Render("CONFIRMATION REQUIRED > ")
		return g, lipgloss.Width(g)
	case m.executing && core.GlobalHitL.HasPending():
		if core.GlobalHitL.PendingKind() == core.ApprovalDuration {
			g := WarningStyle.Render("TOOL APPROVAL (y/n) > ")
			return g, lipgloss.Width(g)
		}
		g := WarningStyle.Render("OPERATOR APPROVAL REQUIRED > ")
		return g, lipgloss.Width(g)
	case m.executing:
		g := PromptGlyphStyle.Render(fmt.Sprintf("%s ❯ ", agName))
		return g, lipgloss.Width(g)
	default:
		g := PromptGlyphStyle.Render(fmt.Sprintf("%s ❯ ", agName))
		return g, lipgloss.Width(g)
	}
}

func wrapStyledLine(line string, width int) string {
	if width <= 0 {
		return ""
	}
	wrapped := lipgloss.NewStyle().Width(width).Render(line)
	lines := strings.Split(wrapped, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return strings.Join(lines, "\n")
}

func (m *Model) updateViewportContent() {
	vpWidth := m.viewport.Width
	vpHeight := m.viewport.Height
	if vpWidth <= 0 {
		vpWidth = max(8, m.width-OutputPaneStyle.GetHorizontalFrameSize())
	}
	if vpHeight <= 0 {
		vpHeight = max(3, m.height-3)
	}

	var base string
	if vpWidth > 4 {
		wrapped := make([]string, len(m.lines))
		for i, line := range m.lines {
			wrapped[i] = wrapStyledLine(line, vpWidth)
		}
		base = strings.Join(wrapped, "\n")
		if m.executing && m.currentResponse != "" {
			base += "\n" + wrapStyledLine(m.renderAgentResponseString(m.currentResponse), vpWidth)
		}
	} else {
		base = strings.Join(m.lines, "\n")
		if m.executing && m.currentResponse != "" {
			base += "\n" + m.renderAgentResponseString(m.currentResponse)
		}
	}

	m.viewport.Width = vpWidth
	m.viewport.Height = vpHeight
	m.viewport.SetContent(base)

	if m.userScrolledUp {
		maxOffset := max(0, m.viewport.TotalLineCount()-m.viewport.Height)
		if m.viewport.YOffset > maxOffset {
			m.viewport.YOffset = maxOffset
		}
	} else {
		if !m.viewport.AtBottom() {
			m.viewport.GotoBottom()
		}
	}
	m.userScrolledUp = !m.viewport.AtBottom()
}

func (m *Model) updateViewportWithLayout(layout tuiLayout) {
	vpWidth := max(8, layout.contentWidth-OutputPaneStyle.GetHorizontalFrameSize())
	vpHeight := max(3, layout.contentHeight-OutputPaneStyle.GetVerticalFrameSize())

	var base string
	if vpWidth > 4 {
		wrapped := make([]string, len(m.lines))
		for i, line := range m.lines {
			wrapped[i] = wrapStyledLine(line, vpWidth)
		}
		base = strings.Join(wrapped, "\n")
		if m.executing && m.currentResponse != "" {
			base += "\n" + wrapStyledLine(m.renderAgentResponseString(m.currentResponse), vpWidth)
		}
	} else {
		base = strings.Join(m.lines, "\n")
		if m.executing && m.currentResponse != "" {
			base += "\n" + m.renderAgentResponseString(m.currentResponse)
		}
	}

	m.viewport.Width = vpWidth
	m.viewport.Height = vpHeight
	m.viewport.SetContent(base)

	if !m.userScrolledUp {
		m.viewport.GotoBottom()
	}
}

func (m Model) renderMainPane(layout tuiLayout) string {
	vpContent := m.viewport.View()
	return MainPaneStyle.Width(layout.mainWidth).Height(layout.mainHeight).Render(vpContent)
}

func (m *Model) appendLine(raw string) {
	clean := stripXMLTags(raw)
	if clean == "" {
		m.lines = append(m.lines, "")
		return
	}

	lines := strings.Split(clean, "\n")
	if len(lines) > 1 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	for _, line := range lines {
		m.lines = append(m.lines, line)
	}
	if len(m.lines) > maxOutputLines {
		m.lines = truncateOutput(m.lines)
	}

	m.updateViewportContent()
}

func (m Model) renderAgentResponseString(content string) string {
	clean := stripXMLTags(content)

	rendered, err := m.mdRenderer.Render(strings.TrimRight(clean, "\n"))
	if err != nil || rendered == "" {
		lines := strings.Split(strings.TrimRight(clean, "\n"), "\n")
		var processed []string
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				processed = append(processed, AgentTextStyle.Render("  "+line))
			} else {
				processed = append(processed, "")
			}
		}
		return strings.Join(processed, "\n")
	}

	lines := strings.Split(rendered, "\n")
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	var processed []string
	inCodeBlock := false
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inCodeBlock = !inCodeBlock
		}

		if inCodeBlock {
			processed = append(processed, CodeBlockStyle.Render(truncateLine(line)))
		} else if strings.HasPrefix(strings.TrimSpace(line), "#") {
			processed = append(processed, AgentHeaderStyle.Render(truncateLine(line)))
		} else if strings.HasPrefix(strings.TrimSpace(line), "*") || strings.HasPrefix(strings.TrimSpace(line), "-") {
			processed = append(processed, AgentListStyle.Render(truncateLine(line)))
		} else {
			processed = append(processed, AgentTextStyle.Render(truncateLine(line)))
		}
	}
	return strings.Join(processed, "\n")
}

func renderSkills(manifest *skills.Manifest, query string) string {
	if manifest == nil || manifest.Count() == 0 {
		return WarningStyle.Render("  [!] No skills loaded.")
	}

	query = strings.TrimSpace(query)
	if query != "" {
		for _, skill := range manifest.Skills {
			if strings.EqualFold(skill.Name, query) {
				return renderSkillDetail(skill)
			}
		}
		return renderSkillSearch(manifest, query)
	}

	counts := map[string]int{}
	for _, skill := range manifest.Skills {
		counts[classifySkill(skill)]++
	}
	categories := make([]string, 0, len(counts))
	for cat := range counts {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	var sb strings.Builder
	sb.WriteString(SectionHeaderStyle.Render(fmt.Sprintf("  LOADED SKILLS (%d total)", manifest.Count())) + "\n")
	sb.WriteString(HintDescStyle.Render("  Type /skills <term> to search modules or /skills <name> for options.") + "\n\n")
	for _, cat := range categories {
		sb.WriteString(fmt.Sprintf("    %-24s %s\n", SidebarLabelStyle.Render(cat), SidebarValueStyle.Render(fmt.Sprintf("%d", counts[cat]))))
	}
	return sb.String()
}

func renderSkillSearch(manifest *skills.Manifest, query string) string {
	q := strings.ToLower(query)
	var matches []skills.Skill
	for _, skill := range manifest.Skills {
		if strings.Contains(strings.ToLower(skill.Name), q) ||
			strings.Contains(strings.ToLower(skill.Description), q) {
			matches = append(matches, skill)
		}
	}

	var sb strings.Builder
	sb.WriteString(SectionHeaderStyle.Render(fmt.Sprintf("  SKILLS MATCHING '%s' (%d)", query, len(matches))) + "\n\n")
	if len(matches) == 0 {
		sb.WriteString(WarningStyle.Render("    No skills found matching search criteria."))
		return sb.String()
	}
	limit := min(len(matches), 12)
	for i := 0; i < limit; i++ {
		skill := matches[i]
		sb.WriteString(fmt.Sprintf("    %-28s %-16s %s\n", HintCmdStyle.Render(skill.Name), SidebarLabelStyle.Render(classifySkill(skill)), HintDescStyle.Render(truncate(skill.Description, 60))))
	}
	return sb.String()
}

func renderSkillDetail(skill skills.Skill) string {
	var sb strings.Builder
	sb.WriteString(HeaderBrandStyle.Render("  "+skill.Name) + "\n")
	sb.WriteString(HintDescStyle.Render("  "+skill.Description) + "\n\n")
	sb.WriteString(fmt.Sprintf("  Category: %s | Backend: %s\n", classifySkill(skill), fallback(skill.ExecutesVia, "system")))
	return sb.String()
}

func skillHasParam(skill skills.Skill, query string) bool {
	for name, param := range skill.Parameters {
		if strings.Contains(strings.ToLower(name), query) || strings.Contains(strings.ToLower(param.Description), query) {
			return true
		}
	}
	return false
}

func classifySkill(skill skills.Skill) string {
	text := strings.ToLower(skill.Name + " " + skill.Description)
	switch {
	case strings.Contains(text, "active directory") || strings.Contains(text, "domain"):
		return "Active Directory"
	case strings.Contains(text, "cloud") || strings.Contains(text, "aws") || strings.Contains(text, "azure"):
		return "Cloud Security"
	case strings.Contains(text, "exploit") || strings.Contains(text, "payload"):
		return "Exploitation"
	case strings.Contains(text, "nmap") || strings.Contains(text, "recon") || strings.Contains(text, "scan"):
		return "Reconnaissance"
	case strings.Contains(text, "web") || strings.Contains(text, "sql") || strings.Contains(text, "xss"):
		return "Web Application"
	default:
		return "General Security"
	}
}

func fallback(value, def string) string {
	if strings.TrimSpace(value) == "" {
		return def
	}
	return value
}

// allHints powers the inline command palette and prefix completion. It is
// derived from the slash-command registry so the palette can never drift from
// the dispatch table. Built in init() because the registry itself is populated
// in init() (commands.go), and var initializers in this file run before that.
var allHints []cmdHint

func init() { allHints = buildCommandHints() }

func buildCommandHints() []cmdHint {
	out := make([]cmdHint, 0, len(slashCommands)*2)
	for _, c := range slashCommands {
		for _, n := range c.names {
			out = append(out, cmdHint{cmd: n, desc: c.desc})
		}
	}
	return out
}

func (m Model) renderHints() string {
	if len(m.hints) == 0 {
		return ""
	}

	maxVisible := 6
	hints := m.hints
	if len(hints) > maxVisible {
		hints = hints[:maxVisible]
	}

	startIdx := 0
	if m.selectedHint >= maxVisible {
		startIdx = m.selectedHint - maxVisible + 1
	}

	headerStyle := lipgloss.NewStyle().
		Foreground(m.theme.TextMuted).
		Bold(true)
	content := headerStyle.Render("COMMANDS") + "\n"

	navHint := lipgloss.NewStyle().Foreground(m.theme.TextDim).Render("↑↓ select · Tab accept")
	content += navHint + "\n"

	panelWidth := min(m.width, 72)
	innerW := max(20, panelWidth-4) // minus border+padding
	var lines []string
	for i := startIdx; i < len(hints) && i-startIdx < maxVisible; i++ {
		h := hints[i]
		prefix := "  "
		cmdStr := HintCmdStyle.Render(h.cmd)
		if i == m.selectedHint {
			prefix = lipgloss.NewStyle().Foreground(m.theme.Primary).Bold(true).Render(" ▸")
			cmdStr = lipgloss.NewStyle().Foreground(m.theme.Primary).Bold(true).Render(h.cmd)
		}
		// Keep each hint on exactly one row — no wrap. Truncate desc to fit panel.
		cmdW := lipgloss.Width(h.cmd) + 3 // prefix + gap
		descAvail := max(8, innerW-cmdW-2)
		descStr := HintDescStyle.Render(truncateVisible(h.desc, descAvail))
		lines = append(lines, fmt.Sprintf("%s %s  %s", prefix, cmdStr, descStr))
	}

	content += strings.Join(lines, "\n")

	panel := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(m.theme.BorderActive).
		Background(m.theme.BackgroundPanel).
		Padding(0, 1).
		Width(panelWidth)

	return panel.Render(content)
}

func matchHints(input string) []cmdHint {
	query := strings.ToLower(strings.TrimSpace(input))
	if query == "" || !strings.HasPrefix(query, "/") {
		return nil
	}
	lowerInput := strings.ToLower(input)
	if strings.HasPrefix(lowerInput, "/set ") || strings.HasPrefix(lowerInput, "/config set ") {
		return matchConfigHints(input)
	}
	var out []cmdHint
	seen := make(map[string]bool)
	for _, h := range allHints {
		if strings.HasPrefix(strings.ToLower(h.cmd), query) {
			if !seen[h.cmd] {
				seen[h.cmd] = true
				out = append(out, h)
			}
		}
	}
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

var configKeys = []cmdHint{
	{cmd: "AUTOPILOT", desc: "Toggle auto-accept (on/off, alias: EXECUTION_MODE)"},
	{cmd: "EXECUTION_MODE", desc: "Execution mode (manual/autonomous)"},
	{cmd: "OPSEC", desc: "Evasion level (high/medium/low, alias: EVASION)"},
	{cmd: "EVASION", desc: "Evasion level (high/medium/low, alias: OPSEC)"},
	{cmd: "SANDBOX", desc: "Docker sandbox (on/off, alias: ISOLATION)"},
	{cmd: "ISOLATION", desc: "Docker sandbox (on/off, alias: SANDBOX)"},
	{cmd: "THEME", desc: "Color theme (dark/light/dracula/nord/gruvbox)"},
	{cmd: "AI_PROVIDER", desc: "AI provider (openrouter/nvidia/openai/gemini/ollama)"},
	{cmd: "AI_MODEL", desc: "Model name for current provider"},
	{cmd: "ROUTER_MODE", desc: "Routing mode (auto/local/9router/off)"},
	{cmd: "NINEROUTER_API_KEY", desc: "9Router API key"},
}

func matchConfigHints(input string) []cmdHint {
	lower := strings.ToLower(strings.TrimSpace(input))
	prefix := ""
	after := ""
	if strings.HasPrefix(lower, "/config set ") {
		prefix = input[:len("/config set ")]
		after = strings.TrimSpace(input[len("/config set "):])
	} else if strings.HasPrefix(lower, "/set ") {
		prefix = input[:len("/set ")]
		after = strings.TrimSpace(input[len("/set "):])
	}
	q := strings.ToLower(after)
	var out []cmdHint
	for _, k := range configKeys {
		if q == "" || strings.HasPrefix(strings.ToLower(k.cmd), q) {
			out = append(out, cmdHint{cmd: prefix + k.cmd, desc: k.desc})
		}
	}
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	if n <= 3 {
		return string(runes[:n])
	}
	return string(runes[:n-1]) + "…"
}

var helpCategoryTitles = map[string]string{
	catOperations: "OPERATIONS  —  Active Tasks",
	catControls:   "CONTROLS  —  Settings",
	catSession:    "SESSION  —  Metrics & Lifecycle",
	catUI:         "UI  —  Display",
}

var helpCategoryOrder = []string{catOperations, catControls, catSession, catUI}

// renderHelp draws the full command reference. Every slash command listed here
// is rendered straight from the shared slashCommands registry — the dispatch
// table — so an undocumented or orphaned command is impossible by construction.
func renderHelp() string {
	var sb strings.Builder
	sb.WriteString("\n  " + SectionHeaderStyle.Render("COMMAND REFERENCE") + "\n")
	sb.WriteString("  " + SectionRuleStyle.Render(strings.Repeat("─", 48)) + "\n\n")

	for _, cat := range helpCategoryOrder {
		var entries []slashCommand
		for _, c := range slashCommands {
			if c.category == cat {
				entries = append(entries, c)
			}
		}
		if len(entries) == 0 {
			continue
		}
		sb.WriteString("  " + SectionHeaderStyle.Render(helpCategoryTitles[cat]) + "\n")
		for _, c := range entries {
			label := c.canonical()
			if c.args != "" {
				label += " " + c.args
			}
			pad := strings.Repeat(" ", max(1, 22-len(label)))
			sb.WriteString("    " + HintCmdStyle.Render(label) + pad + HintDescStyle.Render(c.desc) + "\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("  " + SectionHeaderStyle.Render("KEYBOARD CONTROLS") + "\n")
	keyboard := []cmdHint{
		{"Ctrl+P", "Open command palette"},
		{"Ctrl+B", "Toggle sidebar panel"},
		{"Ctrl+T", "Toggle tool detail panel"},
		{"Ctrl+A", "Toggle autopilot"},
		{"Ctrl+S", "Show session status"},
		{"Ctrl+D", "Show token usage / cost"},
		{"Ctrl+E", "Open output in pager"},
		{"Ctrl+Y", "Copy transcript"},
		{"Ctrl+C", "Cancel task (double-press) or quit"},
		{"↑/↓", "Scroll output"},
		{"Alt+↑/↓", "Browse input history"},
		{"PgUp/Dn", "Page scroll"},
		{"Tab", "Accept command suggestion"},
		{"Enter", "Submit"},
	}
	for _, k := range keyboard {
		pad := strings.Repeat(" ", max(1, 22-len(k.cmd)))
		sb.WriteString("    " + HintCmdStyle.Render(k.cmd) + pad + HintDescStyle.Render(k.desc) + "\n")
	}
	sb.WriteString("\n")

	sb.WriteString("  " + SectionHeaderStyle.Render("LEADER KEY (Ctrl+X then)") + "\n")
	leader := []cmdHint{
		{"b", "Toggle sidebar"},
		{"n", "Start a new session"},
		{"q", "Quit"},
	}
	for _, k := range leader {
		pad := strings.Repeat(" ", max(1, 22-len(k.cmd)))
		sb.WriteString("    " + HintCmdStyle.Render(k.cmd) + pad + HintDescStyle.Render(k.desc) + "\n")
	}
	sb.WriteString("\n")
	sb.WriteString("  " + HintDescStyle.Render("Tip: type /<command> and press Tab to accept, or Ctrl+P for the palette.") + "\n\n")

	return sb.String()
}

func renderSidebarPhase(phase string) string {
	switch strings.ToLower(strings.TrimSpace(phase)) {
	case "planning":
		return PhasePlanningStyle.Render("Planning")
	case "reasoning":
		return PhaseReasoningStyle.Render("Reasoning")
	case "executing", "running":
		return PhaseExecutingStyle.Render("Executing")
	case "verifying", "waiting":
		return PhaseVerifyingStyle.Render("Verifying")
	case "complete", "done":
		return PhaseCompleteStyle.Render("Complete")
	case "error", "failed":
		return PhaseErrorStyle.Render("Error")
	default:
		return PhaseIdleStyle.Render("Idle")
	}
}

func renderPhaseBadge(phase string) (string, lipgloss.Style) {
	s := strings.ToLower(strings.TrimSpace(phase))
	switch s {
	case "planning":
		return PhasePlanningStyle.Render("PLANNING"), PhasePlanningStyle
	case "reasoning":
		return PhaseReasoningStyle.Render("REASONING"), PhaseReasoningStyle
	case "executing", "running":
		return PhaseExecutingStyle.Render("EXECUTING"), PhaseExecutingStyle
	case "verifying", "waiting":
		return PhaseVerifyingStyle.Render("VERIFYING"), PhaseVerifyingStyle
	case "complete", "done":
		return PhaseCompleteStyle.Render("COMPLETE"), PhaseCompleteStyle
	case "error", "failed":
		return PhaseErrorStyle.Render("ERROR"), PhaseErrorStyle
	default:
		return PhaseIdleStyle.Render("IDLE"), PhaseIdleStyle
	}
}

var xmlTagRegex = regexp.MustCompile(`(?s)<environment_details>.*?</environment_details>|<thinking>.*?</thinking>|<plan>.*?</plan>|<status>.*?</status>|<system_prompt>.*?</system_prompt>|<directive>.*?</directive>`)

func stripXMLTags(s string) string {
	return xmlTagRegex.ReplaceAllString(s, "")
}

func (m Model) renderBenchmarks() string {
	content, err := os.ReadFile("BENCHMARKS.md")
	if err != nil {
		content, err = os.ReadFile("../../BENCHMARKS.md")
	}
	if err != nil {
		return ErrorStyle.Render("  [✗] BENCHMARKS.md file not found in workspace root.")
	}

	rendered, err := m.mdRenderer.Render(string(content))
	if err != nil {
		return string(content)
	}
	return rendered
}

func ColorizeElapsed(elapsed string) string {
	switch {
	case elapsed == "idle":
		return StatusOffStyle.Render("○ idle")
	case strings.Contains(elapsed, "m") || strings.Contains(elapsed, "h"):
		return WarningStyle.Render("⏱ " + elapsed)
	default:
		return StatusOnStyle.Render("● " + elapsed)
	}
}

func (m *Model) renderSplash() string {
	w := m.width
	if w <= 0 {
		if tw, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && tw > 0 {
			w = tw
		} else {
			w = 80
		}
	}

	logoStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#f85149")).
		Bold(true)
	subStyle := lipgloss.NewStyle().
		Foreground(m.theme.TextMuted)
	dimStyle := lipgloss.NewStyle().
		Foreground(m.theme.TextDim)

	claw := []string{
		"                    .=#%%+::",
		"                .:-*%@@*=+**",
		"              .=*##%@%:=***=",
		"            =-#%#*=.*+==++-.",
		"          +%#*@%*#%=--=..",
		"       :=-===%#-*@+-*+=",
		"   : =*#=:+#=.-*==+-.:#%:",
		"  +#:-===*%=-.%%=:*-:*+##.",
		" .%*= --+**+ =%*=.   :*=-=%.",
		"++=+ .@%.:: :*=-=      :-+*.",
		"#+#  =@+*   %@*=       #++#",
		"+#.  ++*=   *###       =*%-",
		".#  =%-+    -++:      .*+.",
		"  . -@=*    +@=:      -.",
		"     ##.    .%*.",
		"     .#=     -@:",
		"       =      :-",
	}

	textLine := "D r o g o n C l a w"
	subLine := "Autonomous AI Security Testing"

	var sb strings.Builder

	totalHeight := len(claw) + 5
	padTop := max(0, (m.height-totalHeight)/2)
	for i := 0; i < padTop; i++ {
		sb.WriteString("\n")
	}

	for _, line := range claw {
		padLeft := max(0, (w-len(line))/2)
		sb.WriteString(strings.Repeat(" ", padLeft))
		sb.WriteString(logoStyle.Render(line))
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	textPad := max(0, (w-len(textLine))/2)
	sb.WriteString(strings.Repeat(" ", textPad))
	sb.WriteString(logoStyle.Render(textLine))
	sb.WriteString("\n")

	subPad := max(0, (w-len(subLine))/2)
	sb.WriteString(strings.Repeat(" ", subPad))
	sb.WriteString(subStyle.Render(subLine))
	sb.WriteString("\n\n")

	dimText := "Initializing..."
	dimPad := max(0, (w-len(dimText))/2)
	sb.WriteString(strings.Repeat(" ", dimPad))
	sb.WriteString(dimStyle.Render(dimText))

	return sb.String()
}
