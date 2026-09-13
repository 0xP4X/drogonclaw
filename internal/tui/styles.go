package tui

import (
	"sort"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// Theme holds all color definitions for the TUI
type Theme struct {
	// Primary colors
	Primary   lipgloss.Color
	Secondary lipgloss.Color
	Accent    lipgloss.Color

	// Status colors
	Success lipgloss.Color
	Warning lipgloss.Color
	Error   lipgloss.Color
	Info    lipgloss.Color

	// Text colors
	Text      lipgloss.Color
	TextMuted lipgloss.Color
	TextDim   lipgloss.Color

	// Background colors
	Background        lipgloss.Color
	BackgroundPanel   lipgloss.Color
	BackgroundSurface lipgloss.Color

	// Border colors
	Border       lipgloss.Color
	BorderActive lipgloss.Color
	BorderSubtle lipgloss.Color
}

// DefaultTheme is the dark theme matching OpenCode's style
var DefaultTheme = Theme{
	Primary:   lipgloss.Color("#58a6ff"),
	Secondary: lipgloss.Color("#3fb950"),
	Accent:    lipgloss.Color("#79c0ff"),

	Success: lipgloss.Color("#3fb950"),
	Warning: lipgloss.Color("#d29922"),
	Error:   lipgloss.Color("#f85149"),
	Info:    lipgloss.Color("#58a6ff"),

	Text:      lipgloss.Color("#c9d1d9"),
	TextMuted: lipgloss.Color("#8b949e"),
	TextDim:   lipgloss.Color("#6e7681"),

	Background:        lipgloss.Color("#0d1117"),
	BackgroundPanel:   lipgloss.Color("#161b22"),
	BackgroundSurface: lipgloss.Color("#21262d"),

	Border:       lipgloss.Color("#30363d"),
	BorderActive: lipgloss.Color("#58a6ff"),
	BorderSubtle: lipgloss.Color("#21262d"),
}

// LightTheme is a light variant for daytime use
var LightTheme = Theme{
	Primary:   lipgloss.Color("#0969da"),
	Secondary: lipgloss.Color("#1a7f37"),
	Accent:    lipgloss.Color("#0550ae"),

	Success: lipgloss.Color("#1a7f37"),
	Warning: lipgloss.Color("#9a6700"),
	Error:   lipgloss.Color("#d1242f"),
	Info:    lipgloss.Color("#0969da"),

	Text:      lipgloss.Color("#1f2328"),
	TextMuted: lipgloss.Color("#656d76"),
	TextDim:   lipgloss.Color("#8c959f"),

	Background:        lipgloss.Color("#ffffff"),
	BackgroundPanel:   lipgloss.Color("#f6f8fa"),
	BackgroundSurface: lipgloss.Color("#eaeef2"),

	Border:       lipgloss.Color("#d0d7de"),
	BorderActive: lipgloss.Color("#0969da"),
	BorderSubtle: lipgloss.Color("#eaeef2"),
}

// DraculaTheme is the popular Dracula color scheme
var DraculaTheme = Theme{
	Primary:   lipgloss.Color("#bd93f9"),
	Secondary: lipgloss.Color("#50fa7b"),
	Accent:    lipgloss.Color("#8be9fd"),

	Success: lipgloss.Color("#50fa7b"),
	Warning: lipgloss.Color("#f1fa8c"),
	Error:   lipgloss.Color("#ff5555"),
	Info:    lipgloss.Color("#8be9fd"),

	Text:      lipgloss.Color("#f8f8f2"),
	TextMuted: lipgloss.Color("#6272a4"),
	TextDim:   lipgloss.Color("#44475a"),

	Background:        lipgloss.Color("#282a36"),
	BackgroundPanel:   lipgloss.Color("#343746"),
	BackgroundSurface: lipgloss.Color("#44475a"),

	Border:       lipgloss.Color("#44475a"),
	BorderActive: lipgloss.Color("#bd93f9"),
	BorderSubtle: lipgloss.Color("#343746"),
}

// NordTheme is the Nord arctic color palette
var NordTheme = Theme{
	Primary:   lipgloss.Color("#88c0d0"),
	Secondary: lipgloss.Color("#a3be8c"),
	Accent:    lipgloss.Color("#81a1c1"),

	Success: lipgloss.Color("#a3be8c"),
	Warning: lipgloss.Color("#ebcb8b"),
	Error:   lipgloss.Color("#bf616a"),
	Info:    lipgloss.Color("#88c0d0"),

	Text:      lipgloss.Color("#eceff4"),
	TextMuted: lipgloss.Color("#8fbcbb"),
	TextDim:   lipgloss.Color("#616e88"),

	Background:        lipgloss.Color("#2e3440"),
	BackgroundPanel:   lipgloss.Color("#3b4252"),
	BackgroundSurface: lipgloss.Color("#434c5e"),

	Border:       lipgloss.Color("#434c5e"),
	BorderActive: lipgloss.Color("#88c0d0"),
	BorderSubtle: lipgloss.Color("#3b4252"),
}

// GruvboxTheme is the warm retro groove palette
var GruvboxTheme = Theme{
	Primary:   lipgloss.Color("#fabd2f"),
	Secondary: lipgloss.Color("#b8bb26"),
	Accent:    lipgloss.Color("#83a598"),

	Success: lipgloss.Color("#b8bb26"),
	Warning: lipgloss.Color("#fabd2f"),
	Error:   lipgloss.Color("#fb4934"),
	Info:    lipgloss.Color("#83a598"),

	Text:      lipgloss.Color("#ebdbb2"),
	TextMuted: lipgloss.Color("#a89984"),
	TextDim:   lipgloss.Color("#928374"),

	Background:        lipgloss.Color("#282828"),
	BackgroundPanel:   lipgloss.Color("#3c3836"),
	BackgroundSurface: lipgloss.Color("#504945"),

	Border:       lipgloss.Color("#504945"),
	BorderActive: lipgloss.Color("#fabd2f"),
	BorderSubtle: lipgloss.Color("#3c3836"),
}

// Themes registry — single source of truth for theme names
var Themes = map[string]Theme{
	"dark":    DefaultTheme,
	"light":   LightTheme,
	"dracula": DraculaTheme,
	"nord":    NordTheme,
	"gruvbox": GruvboxTheme,
}

// GetTheme returns the theme for a given name (case-insensitive), falling back to DefaultTheme
func GetTheme(name string) Theme {
	if t, ok := Themes[normalizeThemeName(name)]; ok {
		return t
	}
	return DefaultTheme
}

// ListThemes returns sorted theme names derived from the Themes registry
func ListThemes() []string {
	keys := make([]string, 0, len(Themes))
	for k := range Themes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func normalizeThemeName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// Style helpers
func (t Theme) HeaderStyle() lipgloss.Style {
	return lipgloss.NewStyle().
		Foreground(t.Primary).
		Bold(true)
}

func (t Theme) PanelStyle() lipgloss.Style {
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(t.Border).
		Padding(0, 1)
}

// ApplyTheme rebuilds all global lipgloss styles and color variables from the
// given theme so a mid-session /theme switch recolours the entire TUI without
// requiring a restart. Call it once at startup and on every theme change.
func ApplyTheme(t Theme) {
	// Update legacy color variables so any direct Color* use reflects the theme.
	ColorBg = t.Background
	ColorBgPanel = t.BackgroundPanel
	ColorBgSurface = t.BackgroundSurface
	ColorBgAccent = t.BackgroundSurface
	ColorBright = t.Text
	ColorWhite = t.Text
	ColorSubtle = t.TextMuted
	ColorMuted = t.TextMuted
	ColorDim = t.TextDim
	ColorGhost = t.BorderSubtle
	ColorAccent = t.Primary
	ColorAccent2 = t.Secondary
	ColorAccent3 = t.TextMuted
	ColorSuccess = t.Success
	ColorDanger = t.Error
	ColorWarning = t.Warning
	ColorGold = t.Warning
	ColorCyan = t.Accent
	ColorPurple = t.Primary
	ColorOrange = t.Error
	ColorOutputInfo = t.TextMuted
	ColorOutputDebug = t.TextDim
	ColorOutputSuccess = t.Secondary
	ColorOutputError = t.Error
	ColorOutputWarn = t.Warning
	ColorOutputSignal = t.Primary
	ColorBorder = t.Border
	ColorBorderSoft = t.BorderSubtle

	// Rebuild all style vars from the new palette.
	HeaderBrandStyle = lipgloss.NewStyle().Foreground(t.Primary).Bold(true)
	HeaderSepStyle = lipgloss.NewStyle().Foreground(t.Border).Bold(true)
	HeaderInfoStyle = lipgloss.NewStyle().Foreground(t.TextMuted)
	HeaderDimStyle = lipgloss.NewStyle().Foreground(t.TextDim)
	StatusLabelStyle = lipgloss.NewStyle().Foreground(t.TextDim)
	StatusOnStyle = lipgloss.NewStyle().Foreground(t.Success).Bold(true)
	StatusOffStyle = lipgloss.NewStyle().Foreground(t.TextDim)
	StatusNodeStyle = lipgloss.NewStyle().Foreground(t.Primary).Bold(true)
	StatusAlertStyle = lipgloss.NewStyle().Foreground(t.Error).Bold(true)
	HeaderBarStyle = lipgloss.NewStyle().Foreground(t.TextMuted)
	StatusBarStyle = lipgloss.NewStyle().Foreground(t.TextMuted)

	PhaseIdleStyle = lipgloss.NewStyle().Foreground(t.TextDim).Bold(true)
	PhasePlanningStyle = lipgloss.NewStyle().Foreground(t.Accent).Bold(true)
	PhaseReasoningStyle = lipgloss.NewStyle().Foreground(t.Primary).Bold(true)
	PhaseExecutingStyle = lipgloss.NewStyle().Foreground(t.Warning).Bold(true)
	PhaseVerifyingStyle = lipgloss.NewStyle().Foreground(t.Secondary).Bold(true)
	PhaseCompleteStyle = lipgloss.NewStyle().Foreground(t.Success).Bold(true)
	PhaseErrorStyle = lipgloss.NewStyle().Foreground(t.Error).Bold(true)
	PhaseHitLStyle = lipgloss.NewStyle().Foreground(t.Warning).Bold(true)

	OutputPaneStyle = lipgloss.NewStyle().PaddingLeft(1)
	LineNumberStyle = lipgloss.NewStyle().Foreground(t.TextDim).Width(4).Align(lipgloss.Right)
	ActivityDimStyle = lipgloss.NewStyle().Foreground(t.TextDim)
	MainPaneStyle = lipgloss.NewStyle()
	SidebarPaneStyle = lipgloss.NewStyle()

	AgentTextStyle = lipgloss.NewStyle().Foreground(t.Text)
	AgentHeaderStyle = lipgloss.NewStyle().Foreground(t.Primary).Bold(true)
	AgentSubheaderStyle = lipgloss.NewStyle().Foreground(t.Secondary).Bold(true)
	AgentListStyle = lipgloss.NewStyle().Foreground(t.TextMuted).MarginLeft(2)
	AgentQuoteStyle = lipgloss.NewStyle().Foreground(t.TextDim).Italic(true).BorderLeft(true).BorderForeground(t.Border).PaddingLeft(2).MarginLeft(1)
	CodeBlockStyle = lipgloss.NewStyle().Foreground(t.Text).Background(t.BackgroundSurface).Padding(0, 1)
	InlineCodeStyle = lipgloss.NewStyle().Foreground(t.Error).Background(t.BackgroundSurface).Padding(0, 1)
	KeywordStyle = lipgloss.NewStyle().Foreground(t.Primary).Bold(true)
	StringStyle = lipgloss.NewStyle().Foreground(t.Secondary)
	CommentStyle = lipgloss.NewStyle().Foreground(t.TextDim).Italic(true)
	AgentResponseStyle = lipgloss.NewStyle().Foreground(t.Text).PaddingLeft(1)
	AgentDividerStyle = lipgloss.NewStyle().Foreground(t.Border)

	ToolStartStyle = lipgloss.NewStyle().Foreground(t.Accent).Bold(true).MarginTop(1)
	ToolBorderStyle = lipgloss.NewStyle().Foreground(t.Border)
	ToolErrorStyle = lipgloss.NewStyle().Foreground(t.Error).Bold(true).MarginTop(1)
	ToolDoneStyle = lipgloss.NewStyle().Foreground(t.Success).Bold(true).MarginTop(1)
	ToolArgsStyle = lipgloss.NewStyle().Foreground(t.TextMuted).Italic(true).MarginLeft(2)
	ToolOutputStyle = lipgloss.NewStyle().Foreground(t.TextMuted).MarginLeft(2)
	ToolOutputSuccessStyle = lipgloss.NewStyle().Foreground(t.Secondary).MarginLeft(2)
	ToolOutputErrorStyle = lipgloss.NewStyle().Foreground(t.Error).MarginLeft(2)

	PromptBorderStyle = lipgloss.NewStyle().Foreground(t.Primary).Bold(true)
	PromptAliasStyle = lipgloss.NewStyle().Foreground(t.Primary).Bold(true)
	PromptAtStyle = lipgloss.NewStyle().Foreground(t.TextDim)
	PromptAgentStyle = lipgloss.NewStyle().Foreground(t.Secondary)
	PromptSessionStyle = lipgloss.NewStyle().Foreground(t.TextDim).Italic(true)
	PromptUserStyle = lipgloss.NewStyle().Foreground(t.Text).Bold(true)
	PromptGlyphStyle = lipgloss.NewStyle().Foreground(t.Primary).Bold(true).MarginRight(1)
	InputPaneStyle = lipgloss.NewStyle().Padding(0, 1)

	HintBorderStyle = lipgloss.NewStyle().Foreground(t.TextDim)
	HintCmdStyle = lipgloss.NewStyle().Foreground(t.Primary).Bold(true)
	HintDescStyle = lipgloss.NewStyle().Foreground(t.TextMuted)
	HintSelectedStyle = lipgloss.NewStyle().Foreground(t.Text).Bold(true)

	ErrorStyle = lipgloss.NewStyle().Foreground(t.Error).Bold(true)
	WarningStyle = lipgloss.NewStyle().Foreground(t.Warning)
	InfoStyle = lipgloss.NewStyle().Foreground(t.Accent)
	SpinnerStyle = lipgloss.NewStyle().Foreground(t.Primary)
	QueueStyle = lipgloss.NewStyle().Foreground(t.Primary).Bold(true)
	QueueItemStyle = lipgloss.NewStyle().Foreground(t.TextMuted)
	StatusLineStyle = lipgloss.NewStyle().Foreground(t.TextMuted).Italic(true)
	SignalLineStyle = lipgloss.NewStyle().Foreground(t.Primary).Bold(true)
	DividerStyle = lipgloss.NewStyle().Foreground(t.BorderSubtle)
	SessionStyle = lipgloss.NewStyle().Foreground(t.TextDim)

	EvidenceStyle = lipgloss.NewStyle().Foreground(t.Accent).Italic(true)
	FactStyle = lipgloss.NewStyle().Foreground(t.Text)
	FactKeyStyle = lipgloss.NewStyle().Foreground(t.Primary).Bold(true)
	FactValStyle = lipgloss.NewStyle().Foreground(t.Text)
	TruncatedStyle = lipgloss.NewStyle().Foreground(t.TextDim).Italic(true)

	TreeBranchStyle = lipgloss.NewStyle().Foreground(t.BorderSubtle)
	TreeItemStyle = lipgloss.NewStyle().Foreground(t.Text)
	TreeItemSelectedStyle = lipgloss.NewStyle().Foreground(t.Primary).Bold(true)
	TreeIndentStyle = lipgloss.NewStyle().Foreground(t.BorderSubtle)

	WelcomeTitleStyle = lipgloss.NewStyle().Foreground(t.Primary).Bold(true)
	WelcomeSubtitleStyle = lipgloss.NewStyle().Foreground(t.TextMuted)
	WelcomeHintStyle = lipgloss.NewStyle().Foreground(t.TextDim).Italic(true)
	WelcomeBorderStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(t.Border).Padding(0, 1).Background(t.BackgroundPanel)
	WelcomeQuickStartStyle = lipgloss.NewStyle().Foreground(t.Secondary).Bold(true)

	SidebarTitleStyle = lipgloss.NewStyle().Foreground(t.TextMuted).Bold(true)
	SidebarLabelStyle = lipgloss.NewStyle().Foreground(t.TextDim)
	SidebarValueStyle = lipgloss.NewStyle().Foreground(t.Text)
	SidebarRuleStyle = lipgloss.NewStyle().Foreground(t.BorderSubtle)

	SectionHeaderStyle = lipgloss.NewStyle().Foreground(t.TextMuted).Bold(true)
	SectionRuleStyle = lipgloss.NewStyle().Foreground(t.BorderSubtle)
}

// Legacy color variables for backward compatibility
var (
	ColorBg        = DefaultTheme.Background
	ColorBgPanel   = DefaultTheme.BackgroundPanel
	ColorBgSurface = DefaultTheme.BackgroundSurface
	ColorBgAccent  = lipgloss.Color("#30363d")

	ColorBright = DefaultTheme.Text
	ColorWhite  = lipgloss.Color("#e6edf3")
	ColorSubtle = DefaultTheme.TextMuted
	ColorMuted  = lipgloss.Color("#656d76")
	ColorDim    = DefaultTheme.TextDim
	ColorGhost  = DefaultTheme.BorderSubtle

	ColorAccent  = DefaultTheme.Primary
	ColorAccent2 = DefaultTheme.Secondary
	ColorAccent3 = lipgloss.Color("#a5a5a5")

	ColorSuccess = DefaultTheme.Success
	ColorDanger  = DefaultTheme.Error
	ColorWarning = DefaultTheme.Warning
	ColorGold    = lipgloss.Color("#e3b341")
	ColorCyan    = DefaultTheme.Accent
	ColorPurple  = lipgloss.Color("#bc8cff")
	ColorOrange  = lipgloss.Color("#ff7b72")

	ColorOutputInfo    = DefaultTheme.TextMuted
	ColorOutputDebug   = lipgloss.Color("#656d76")
	ColorOutputSuccess = DefaultTheme.Secondary
	ColorOutputError   = lipgloss.Color("#ff7b72")
	ColorOutputWarn    = lipgloss.Color("#e3b341")
	ColorOutputSignal  = DefaultTheme.Primary

	ColorBorder     = DefaultTheme.Border
	ColorBorderSoft = DefaultTheme.BorderSubtle
)

var (
	HeaderBrandStyle = lipgloss.NewStyle().
		Foreground(ColorAccent).
		Bold(true)

	HeaderSepStyle = lipgloss.NewStyle().
		Foreground(ColorBorder).
		Bold(true)

	HeaderInfoStyle = lipgloss.NewStyle().
		Foreground(ColorSubtle)

	HeaderDimStyle = lipgloss.NewStyle().
		Foreground(ColorDim)

	StatusLabelStyle = lipgloss.NewStyle().
		Foreground(ColorDim)

	StatusOnStyle = lipgloss.NewStyle().
		Foreground(ColorSuccess).
		Bold(true)

	StatusOffStyle = lipgloss.NewStyle().
		Foreground(ColorDim)

	StatusNodeStyle = lipgloss.NewStyle().
		Foreground(ColorAccent).
		Bold(true)

	StatusAlertStyle = lipgloss.NewStyle().
		Foreground(ColorDanger).
		Bold(true)

	HeaderBarStyle = lipgloss.NewStyle().
		Foreground(ColorSubtle)

	StatusBarStyle = lipgloss.NewStyle().
		Foreground(ColorSubtle)
)

var (
	PhaseIdleStyle = lipgloss.NewStyle().
		Foreground(ColorDim).
		Bold(true)

	PhasePlanningStyle = lipgloss.NewStyle().
		Foreground(ColorCyan).
		Bold(true)

	PhaseReasoningStyle = lipgloss.NewStyle().
		Foreground(ColorPurple).
		Bold(true)

	PhaseExecutingStyle = lipgloss.NewStyle().
		Foreground(ColorWarning).
		Bold(true)

	PhaseVerifyingStyle = lipgloss.NewStyle().
		Foreground(ColorAccent2).
		Bold(true)

	PhaseCompleteStyle = lipgloss.NewStyle().
		Foreground(ColorSuccess).
		Bold(true)

	PhaseErrorStyle = lipgloss.NewStyle().
		Foreground(ColorDanger).
		Bold(true)

	PhaseHitLStyle = lipgloss.NewStyle().
		Foreground(ColorWarning).
		Bold(true)
)

var (
	OutputPaneStyle = lipgloss.NewStyle().
		PaddingLeft(1)

	LineNumberStyle = lipgloss.NewStyle().
		Foreground(ColorDim).
		Width(4).
		Align(lipgloss.Right)

	ActivityDimStyle = lipgloss.NewStyle().
		Foreground(ColorDim)

	MainPaneStyle = lipgloss.NewStyle()

	SidebarPaneStyle = lipgloss.NewStyle()
)

var (
	AgentTextStyle = lipgloss.NewStyle().
		Foreground(ColorWhite)

	AgentHeaderStyle = lipgloss.NewStyle().
		Foreground(ColorAccent).
		Bold(true)

	AgentSubheaderStyle = lipgloss.NewStyle().
		Foreground(ColorAccent2).
		Bold(true)

	AgentListStyle = lipgloss.NewStyle().
		Foreground(ColorSubtle).
		MarginLeft(2)

	AgentQuoteStyle = lipgloss.NewStyle().
		Foreground(ColorDim).
		Italic(true).
		BorderLeft(true).
		BorderForeground(ColorBorder).
		PaddingLeft(2).
		MarginLeft(1)

	CodeBlockStyle = lipgloss.NewStyle().
		Foreground(ColorBright).
		Background(ColorBgAccent).
		Padding(0, 1)

	InlineCodeStyle = lipgloss.NewStyle().
		Foreground(ColorOrange).
		Background(ColorBgAccent).
		Padding(0, 1)

	KeywordStyle = lipgloss.NewStyle().
		Foreground(ColorPurple).
		Bold(true)

	StringStyle = lipgloss.NewStyle().
		Foreground(ColorAccent2)

	CommentStyle = lipgloss.NewStyle().
		Foreground(ColorDim).
		Italic(true)

	AgentResponseStyle = lipgloss.NewStyle().
		Foreground(ColorWhite).
		PaddingLeft(1)

	AgentDividerStyle = lipgloss.NewStyle().
		Foreground(ColorBorder)
)

var (
	ToolStartStyle = lipgloss.NewStyle().
		Foreground(ColorCyan).
		Bold(true).
		MarginTop(1)

	ToolBorderStyle = lipgloss.NewStyle().
		Foreground(ColorBorder)

	ToolErrorStyle = lipgloss.NewStyle().
		Foreground(ColorDanger).
		Bold(true).
		MarginTop(1)

	ToolDoneStyle = lipgloss.NewStyle().
		Foreground(ColorSuccess).
		Bold(true).
		MarginTop(1)

	SubagentBadgeStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#0d1117")).
		Background(lipgloss.Color("#79c0ff")).
		Bold(true).
		Padding(0, 1)

	SubagentTextStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#79c0ff")).
		Bold(true)

	ToolArgsStyle = lipgloss.NewStyle().
		Foreground(ColorSubtle).
		Italic(true).
		MarginLeft(2)

	ToolOutputStyle = lipgloss.NewStyle().
		Foreground(ColorOutputInfo).
		MarginLeft(2)

	ToolOutputSuccessStyle = lipgloss.NewStyle().
		Foreground(ColorOutputSuccess).
		MarginLeft(2)

	ToolOutputErrorStyle = lipgloss.NewStyle().
		Foreground(ColorOutputError).
		MarginLeft(2)
)

var (
	PromptBorderStyle = lipgloss.NewStyle().
		Foreground(ColorAccent).
		Bold(true)

	PromptAliasStyle = lipgloss.NewStyle().
		Foreground(ColorAccent).
		Bold(true)

	PromptAtStyle = lipgloss.NewStyle().
		Foreground(ColorDim)

	PromptAgentStyle = lipgloss.NewStyle().
		Foreground(ColorAccent2)

	PromptSessionStyle = lipgloss.NewStyle().
		Foreground(ColorDim).
		Italic(true)

	PromptUserStyle = lipgloss.NewStyle().
		Foreground(ColorBright).
		Bold(true)

	PromptGlyphStyle = lipgloss.NewStyle().
		Foreground(ColorAccent).
		Bold(true).
		MarginRight(1)

	InputPaneStyle = lipgloss.NewStyle().
		Padding(0, 1)
)

var (
	HintBorderStyle = lipgloss.NewStyle().
		Foreground(ColorDim)

	HintCmdStyle = lipgloss.NewStyle().
		Foreground(ColorAccent).
		Bold(true)

	HintDescStyle = lipgloss.NewStyle().
		Foreground(ColorMuted)

	HintSelectedStyle = lipgloss.NewStyle().
		Foreground(ColorBright).
		Bold(true)
)

var (
	ErrorStyle = lipgloss.NewStyle().
		Foreground(ColorDanger).
		Bold(true)

	WarningStyle = lipgloss.NewStyle().
		Foreground(ColorWarning)

	InfoStyle = lipgloss.NewStyle().
		Foreground(ColorCyan)

	SpinnerStyle = lipgloss.NewStyle().
		Foreground(ColorAccent)

	QueueStyle = lipgloss.NewStyle().
		Foreground(ColorPurple).
		Bold(true)

	QueueItemStyle = lipgloss.NewStyle().
		Foreground(ColorSubtle)

	StatusLineStyle = lipgloss.NewStyle().
		Foreground(ColorSubtle).
		Italic(true)

	SignalLineStyle = lipgloss.NewStyle().
		Foreground(ColorAccent).
		Bold(true)

	DividerStyle = lipgloss.NewStyle().
		Foreground(ColorGhost)

	SessionStyle = lipgloss.NewStyle().
		Foreground(ColorDim)
)

var (
	EvidenceStyle = lipgloss.NewStyle().
		Foreground(ColorCyan).
		Italic(true)

	FactStyle = lipgloss.NewStyle().
		Foreground(ColorWhite)

	FactKeyStyle = lipgloss.NewStyle().
		Foreground(ColorAccent).
		Bold(true)

	FactValStyle = lipgloss.NewStyle().
		Foreground(ColorWhite)

	TruncatedStyle = lipgloss.NewStyle().
		Foreground(ColorDim).
		Italic(true)
)

var (
	TreeBranchStyle = lipgloss.NewStyle().
		Foreground(ColorGhost)

	TreeItemStyle = lipgloss.NewStyle().
		Foreground(ColorWhite)

	TreeItemSelectedStyle = lipgloss.NewStyle().
		Foreground(ColorAccent).
		Bold(true)

	TreeIndentStyle = lipgloss.NewStyle().
		Foreground(ColorGhost)
)

var (
	WelcomeTitleStyle = lipgloss.NewStyle().
		Foreground(ColorAccent).
		Bold(true)

	WelcomeSubtitleStyle = lipgloss.NewStyle().
		Foreground(ColorMuted)

	WelcomeHintStyle = lipgloss.NewStyle().
		Foreground(ColorDim).
		Italic(true)

	WelcomeBorderStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorder).
		Padding(0, 1).
		Background(ColorBgPanel)

	WelcomeQuickStartStyle = lipgloss.NewStyle().
		Foreground(ColorAccent2).
		Bold(true)
)

var (
	SidebarTitleStyle = lipgloss.NewStyle().
		Foreground(ColorSubtle).
		Bold(true)

	SidebarLabelStyle = lipgloss.NewStyle().
		Foreground(ColorDim)

	SidebarValueStyle = lipgloss.NewStyle().
		Foreground(ColorWhite)

	SidebarRuleStyle = lipgloss.NewStyle().
		Foreground(ColorGhost)
)

var (
	SectionHeaderStyle = lipgloss.NewStyle().
		Foreground(ColorSubtle).
		Bold(true)

	SectionRuleStyle = lipgloss.NewStyle().
		Foreground(ColorGhost)
)

func PhaseStyle(phase string) lipgloss.Style {
	switch phase {
	case "idle":
		return PhaseIdleStyle
	case "planning":
		return PhasePlanningStyle
	case "reasoning":
		return PhaseReasoningStyle
	case "executing":
		return PhaseExecutingStyle
	case "verifying":
		return PhaseVerifyingStyle
	case "complete":
		return PhaseCompleteStyle
	case "error":
		return PhaseErrorStyle
	default:
		return PhaseIdleStyle
	}
}

func CustomHuhTheme() *huh.Theme {
	t := huh.ThemeBase()

	t.Focused.Base = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(ColorAccent).
		PaddingLeft(2)
	t.Blurred.Base = lipgloss.NewStyle().PaddingLeft(3)

	t.Focused.Title = lipgloss.NewStyle().Foreground(ColorAccent).Bold(true)
	t.Blurred.Title = lipgloss.NewStyle().Foreground(ColorDim)
	t.Focused.Description = lipgloss.NewStyle().Foreground(ColorSubtle)
	t.Blurred.Description = lipgloss.NewStyle().Foreground(ColorDim)

	t.Focused.Option = lipgloss.NewStyle().Foreground(ColorWhite)
	t.Focused.SelectedOption = lipgloss.NewStyle().Foreground(ColorAccent).Bold(true)
	t.Focused.UnselectedOption = lipgloss.NewStyle().Foreground(ColorDim)

	t.Focused.TextInput.Cursor = lipgloss.NewStyle().Foreground(ColorAccent)
	t.Focused.TextInput.Text = lipgloss.NewStyle().Foreground(ColorWhite)
	t.Focused.TextInput.Placeholder = lipgloss.NewStyle().Foreground(ColorDim)
	t.Focused.TextInput.Prompt = lipgloss.NewStyle().Foreground(ColorAccent2)

	t.Focused.SelectSelector = lipgloss.NewStyle().Foreground(ColorAccent)
	t.Focused.MultiSelectSelector = lipgloss.NewStyle().Foreground(ColorAccent)
	t.Focused.SelectedPrefix = lipgloss.NewStyle().Foreground(ColorSuccess)
	t.Focused.UnselectedPrefix = lipgloss.NewStyle().Foreground(ColorDim)

	t.Focused.FocusedButton = lipgloss.NewStyle().
		Foreground(ColorBg).
		Background(ColorAccent).
		Bold(true).
		Padding(0, 1)
	t.Focused.BlurredButton = lipgloss.NewStyle().
		Foreground(ColorWhite).
		Background(ColorBgAccent).
		Padding(0, 1)

	t.Help.Ellipsis = lipgloss.NewStyle().Foreground(ColorDim)
	t.Help.ShortKey = lipgloss.NewStyle().Foreground(ColorSubtle)
	t.Help.ShortDesc = lipgloss.NewStyle().Foreground(ColorDim)
	t.Help.ShortSeparator = lipgloss.NewStyle().Foreground(ColorGhost)
	t.Help.FullKey = lipgloss.NewStyle().Foreground(ColorSubtle)
	t.Help.FullDesc = lipgloss.NewStyle().Foreground(ColorDim)
	t.Help.FullSeparator = lipgloss.NewStyle().Foreground(ColorGhost)

	return t
}
