package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/0xP4X/drogonclaw-go/internal/config"
	"github.com/0xP4X/drogonclaw-go/internal/tui"
	"github.com/charmbracelet/lipgloss"
)

// Build metadata, injected at link time via the Makefile:
//
//	go build -ldflags "-X main.version=... -X main.buildTime=..."
var (
	version   = "dev"
	buildTime = "unknown"
)

// cliAction enumerates the possible outcomes of parsing the command line.
type cliAction int

const (
	actionTUI cliAction = iota
	actionHelp
	actionVersion
	actionSetup
	actionBench
	actionWhitebox
	actionHealth
	actionDaemon
	actionPrompt
)

// cliOptions is the parsed description of the operator's intent.
type cliOptions struct {
	action       cliAction
	forceSandbox *bool
	prompt       string
	outputFormat string
	quiet        bool
	extraArgs    []string
}

// cliEntry describes one subcommand for the reference screen.
type cliEntry struct {
	cmd     string
	usage   string
	summary string
}

// cliEntries is the single source of truth for `./drogonclaw help` and for
// unknown-command hints, so the dispatcher and its documentation cannot drift.
var cliEntries = []cliEntry{
	{"", "", "(no command)  Launch the interactive TUI"},
	{"-p, --prompt", "\"<objective>\" [-f text|json] [-q]", "Run single offensive prompt headlessly without TUI"},
	{"sandbox", "", "Launch the TUI with the Docker/Kali sandbox forced on"},
	{"native", "[<env details>]", "Launch the TUI in native host mode"},
	{"setup", "", "Run the interactive configuration wizard"},
	{"health", "", "Run runtime diagnostics and dependency checks"},
	{"bench", "[--set FILE] [--out DIR] [-c N] [--timeout D]", "Run the autonomous benchmark suite"},
	{"whitebox", "-u URL [-r REPO] [-o OUT] [-s SESSION] [--no-verify]", "Run the autonomous white-box web/API pipeline"},
	{"daemon", "", "Run headless as a Telegram daemon"},
	{"version", "", "Print build version and metadata"},
	{"help", "", "Show this reference"},
}

var (
	cliTitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#58a6ff")).
			Bold(true)
	cliDimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6e7681"))
	cliMutedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8b949e"))
	cliRuleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#30363d"))
	cliCmdStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#3fb950")).
			Bold(true)
	cliBannerStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#30363d")).
			Background(lipgloss.Color("#0d1117")).
			Padding(0, 2)
)

// runStandaloneCommand executes the subcommands that finish before the runtime
// boots. It reports whether a subcommand was handled; the caller exits with the
// returned code immediately when handled is true, so every terminal action
// shares one exit path.
func runStandaloneCommand(opts cliOptions, cfg *config.Manager) (handled bool, code int) {
	switch opts.action {
	case actionHelp:
		printCLIHelp(os.Stdout)
		return true, 0
	case actionVersion:
		printVersion(os.Stdout)
		return true, 0
	case actionSetup:
		tui.RunSetup(cfg)
		return true, 0
	case actionBench:
		runBenchmark(cfg, opts.extraArgs)
		return true, 0
	case actionWhitebox:
		runWhitebox(cfg, opts.extraArgs)
		return true, 0
	}
	return false, 0
}

// parseCLI inspects the raw arguments and classifies the requested action.
// Unknown commands return a descriptive error so the operator is never silently
// dropped into the TUI on a typo.
func parseCLI(args []string) (cliOptions, error) {
	opts := cliOptions{action: actionTUI, outputFormat: "text"}
	if len(args) == 0 {
		return opts, nil
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "help" || arg == "-h" || arg == "--help":
			opts.action = actionHelp
			return opts, nil
		case arg == "version" || arg == "-v" || arg == "--version":
			opts.action = actionVersion
			return opts, nil
		case arg == "setup":
			opts.action = actionSetup
			return opts, nil
		case arg == "bench":
			opts.action = actionBench
			opts.extraArgs = args[i+1:]
			return opts, nil
		case arg == "whitebox":
			opts.action = actionWhitebox
			opts.extraArgs = args[i+1:]
			return opts, nil
		case arg == "health":
			opts.action = actionHealth
			return opts, nil
		case arg == "daemon":
			opts.action = actionDaemon
			return opts, nil
		case arg == "sandbox":
			t := true
			opts.forceSandbox = &t
		case arg == "native":
			t := false
			opts.forceSandbox = &t
			if i+1 < len(args) {
				opts.extraArgs = args[i+1:]
			}
			return opts, nil
		case arg == "-p" || arg == "--prompt":
			opts.action = actionPrompt
			if i+1 < len(args) {
				opts.prompt = args[i+1]
				i++
			} else {
				return opts, fmt.Errorf("-p/--prompt requires a prompt string")
			}
		case arg == "-f" || arg == "--format" || arg == "--output-format":
			if i+1 < len(args) {
				fmtVal := strings.ToLower(args[i+1])
				if fmtVal != "text" && fmtVal != "json" {
					return opts, fmt.Errorf("invalid format %q: must be 'text' or 'json'", fmtVal)
				}
				opts.outputFormat = fmtVal
				i++
			}
		case arg == "-q" || arg == "--quiet":
			opts.quiet = true
		default:
			if opts.action == actionPrompt {
				// Keep collecting tokens if prompt was unquoted
				if opts.prompt == "" {
					opts.prompt = arg
				} else {
					opts.prompt += " " + arg
				}
			} else {
				return opts, fmt.Errorf("unknown command: %s", arg)
			}
		}
	}
	return opts, nil
}

// applyRunMode applies the forced sandbox/native mode as an environment hint
// and prints a launch banner. It is a no-op when no mode was forced.
func applyRunMode(opts cliOptions) {
	if opts.forceSandbox == nil {
		return
	}
	if *opts.forceSandbox {
		os.Setenv("USE_SANDBOX", "true")
		fmt.Println("  [+] Launching in SANDBOX mode (Docker/Kali)")
		return
	}
	os.Setenv("USE_SANDBOX", "false")
	fmt.Println("  [+] Launching in NATIVE mode (host OS)")
	if len(opts.extraArgs) > 0 {
		fmt.Printf("  [*] Environment details: %s\n", strings.Join(opts.extraArgs, " "))
	}
}

// printVersion prints build identity and runtime metadata.
func printVersion(w io.Writer) {
	fmt.Fprintln(w, cliBannerStyle.Render(
		cliTitleStyle.Render("🐉 DrogonClaw "+version)+
			"\n"+
			cliDimStyle.Render("  build   ")+cliMutedStyle.Render(buildTime)+
			"\n"+
			cliDimStyle.Render("  go      ")+cliMutedStyle.Render(runtime.Version()),
	))
}

// printCLIHelp renders the graphical sub-command reference.
func printCLIHelp(w io.Writer) {
	fmt.Fprintln(w, cliBannerStyle.Render(
		cliTitleStyle.Render("🐉 DrogonClaw — Autonomous Offensive Security AI")+
			"\n"+
			cliDimStyle.Render("usage: drogonclaw [command] [flags]"),
	))
	fmt.Fprintln(w, cliRuleStyle.Render(strings.Repeat("─", 60)))

	maxCmd := 0
	for _, e := range cliEntries {
		if len(e.cmd) > maxCmd {
			maxCmd = len(e.cmd)
		}
	}

	for _, e := range cliEntries {
		left := e.cmd
		if left == "" {
			left = "(none)"
		}
		pad := strings.Repeat(" ", max(1, maxCmd+2-len(left)))
		line := "  " + cliCmdStyle.Render(left) + pad
		if e.usage != "" {
			line += cliMutedStyle.Render(e.usage) + "   "
		}
		fmt.Fprintf(w, "%s%s\n", line, cliDimStyle.Render(e.summary))
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, cliMutedStyle.Render("  Run 'drogonclaw' with no arguments, or 'drogonclaw sandbox' / 'drogonclaw native' to force an execution mode."))
	fmt.Fprintln(w, cliMutedStyle.Render("  Inside the TUI, type /help or press Ctrl+P for the command palette."))
}

// printCLIUnknownError renders the one-line + hint used on a bad subcommand.
func printCLIUnknownError(w io.Writer) {
	fmt.Fprintln(w, cliDimStyle.Render("  Run 'drogonclaw help' for a full list of commands."))
}
