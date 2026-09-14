package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/0xP4X/drogonclaw-go/internal/agent"
	"github.com/0xP4X/drogonclaw-go/internal/benchmark"
	"github.com/0xP4X/drogonclaw-go/internal/billing"
	"github.com/0xP4X/drogonclaw-go/internal/config"
	"github.com/0xP4X/drogonclaw-go/internal/core"
	"github.com/0xP4X/drogonclaw-go/internal/gateway"
	"github.com/0xP4X/drogonclaw-go/internal/health"
	"github.com/0xP4X/drogonclaw-go/internal/intel"
	"github.com/0xP4X/drogonclaw-go/internal/memory"
	"github.com/0xP4X/drogonclaw-go/internal/opsec"
	"github.com/0xP4X/drogonclaw-go/internal/sandbox"
	"github.com/0xP4X/drogonclaw-go/internal/skills"
	"github.com/0xP4X/drogonclaw-go/internal/tui"
	"github.com/0xP4X/drogonclaw-go/internal/whitebox"
	tea "github.com/charmbracelet/bubbletea"
)

func runStartup(cfg *config.Manager, forceSandbox *bool) (*agent.Provider, *sandbox.Docker, *skills.Manifest, error) {
	var manifest *skills.Manifest
	var sb *sandbox.Docker
	var provider *agent.Provider

	steps := []string{
		"Loading skills manifest",
		"Initializing runtime",
		"Connecting to model provider",
		"Preparing workspace",
	}

	err := tui.RunLoadingSteps(steps, func(i int) error {
		switch i {
		case 0:
			var loadErr error
			manifest, loadErr = skills.Load("skills_manifest.json")
			if loadErr != nil {
				manifest = &skills.Manifest{}
			}
			return nil
		case 1:
			var initErr error
			sb, initErr = sandbox.New()
			if initErr != nil {
				return initErr
			}
			initCtx := context.Background()
			native := true
			if forceSandbox != nil {
				native = !*forceSandbox
			} else {
				native = !cfg.IsSandboxEnabled()
			}
			return sb.Initialize(initCtx, native)
		case 2:
			provider = agent.NewProvider(cfg)
			pingCtx, pingCancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer pingCancel()
			if err := provider.Ping(pingCtx); err != nil {
				return diagnoseProviderError(cfg, err)
			}
			return nil
		case 3:
			return nil
		default:
			return nil
		}
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return provider, sb, manifest, nil
}

func main() {
	cfg := config.Get()
	rand.Seed(time.Now().UnixNano())

	core.InitCleanupHandler()
	defer core.PerformCleanup()

	opts, err := parseCLI(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [x] %v\n\n", err)
		printCLIUnknownError(os.Stderr)
		os.Exit(2)
	}

	// Commands that complete without booting the runtime.
	if handled, code := runStandaloneCommand(opts, cfg); handled {
		os.Exit(code)
	}

	applyRunMode(opts)

	provider, sb, manifest, err := runStartup(cfg, opts.forceSandbox)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [x] Startup failed: %v\n", err)
		os.Exit(1)
	}
	tracker := billing.New(nil)
	provider.SetUsageCallback(tracker.Record)

	if sb == nil {
		fmt.Fprintf(os.Stderr, "  [x] Sandbox initialization failed\n")
		os.Exit(1)
	}

	sessionID := fmt.Sprintf("ss%010d", rand.Intn(9000000000)+1000000000)
	graph := memory.NewGraph(sessionID)

	if opName := cfg.GetOperatorName(); opName != "" {
		graph.UpdateOperatorProfile(&memory.OperatorProfile{Name: opName})
	}

	if opts.action == actionHealth {
		out := health.RunDiagnostics(context.Background(), sb)
		fmt.Println(out)
		os.Exit(0)
	}

	lootDb, err := memory.NewLootDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [!] Loot DB init failed: %v\n", err)
	} else {
		defer lootDb.Close()
	}

	validator := agent.NewEvidenceValidator(provider)
	tools := agent.NewToolRegistry(manifest, sb, validator, lootDb, cfg, graph, provider)

	go func() {
		if _, err := intel.LoadCVEDatabase(); err != nil {
			fmt.Fprintf(os.Stderr, "  [!] CVE DB load failed: %v\n", err)
		}
	}()

	opsecMgr := opsec.NewManager()
	sysPrompt := agent.BuildSystemPrompt(graph, opsecMgr, "", sb.RuntimeLabel())
	orch := agent.NewOrchestratorWithJournal(provider, tools, sysPrompt, sessionID, graph, memory.NewActionJournal(sessionID), cfg.GetMaxIterations())

	tgGateway, err := gateway.NewTelegramGateway(cfg, orch, graph, opsecMgr, lootDb)
	if err == nil && tgGateway != nil {
		tgGateway.Start()
	}

	if opts.action == actionDaemon {
		if tgGateway == nil {
			fmt.Fprintf(os.Stderr, "  [x] Cannot run in daemon mode: Telegram gateway is not configured.\n")
			fmt.Fprintf(os.Stderr, "  [!] Run './drogonclaw setup' to configure Telegram.\n")
			os.Exit(1)
		}
		fmt.Println("  [+] DrogonClaw running in Daemon mode. Listening via Telegram...")
		select {}
	}

	if opts.action == actionPrompt {
		runHeadlessPrompt(orch, opts.prompt, opts.outputFormat, opts.quiet)
		os.Exit(0)
	}

	model, err := tui.New(orch, graph, opsecMgr, cfg, manifest, sb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [x] TUI init failed: %v\n", err)
		os.Exit(1)
	}
	model.SetTracker(tracker)

	model.SetPromptRefresher(func() string {
		return agent.BuildSystemPrompt(graph, opsecMgr, "", sb.RuntimeLabel())
	})

	p := tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "  [x] TUI crashed: %v\n", err)
		os.Exit(1)
	}

	if tui.NeedSetup() {
		tui.RunSetup(cfg)
		cfg.Reload()
		bin := os.Args[0]
		if !strings.Contains(bin, "/") && !strings.Contains(bin, "\\") {
			if p, err := exec.LookPath(bin); err == nil {
				bin = p
			}
		}
		_ = syscall.Exec(bin, os.Args, os.Environ())
		os.Exit(0)
	}
}

// runBenchmark handles the `drogonclaw bench` subcommand.
//
//	./drogonclaw bench --set benchmarks/xben/set.json --out benchmark_runs
//
// It loads a challenge set, runs each through the agent's headless ReAct loop,
// and writes an XBEN-style report (report.md + results.json) to the output dir.
func runBenchmark(cfg *config.Manager, args []string) {
	var setPath, outDir string
	timeout := 15 * time.Minute
	concurrency := cfg.GetBenchmarkConcurrency()

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--set", "-set":
			if i+1 < len(args) {
				setPath = args[i+1]
				i++
			}
		case "--out", "-out":
			if i+1 < len(args) {
				outDir = args[i+1]
				i++
			}
		case "--timeout", "-timeout":
			if i+1 < len(args) {
				if d, err := time.ParseDuration(args[i+1]); err == nil {
					timeout = d
				}
				i++
			}
		case "--concurrency", "-c":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n >= 1 {
					concurrency = n
				}
				i++
			}
		default:
			if setPath == "" && !strings.HasPrefix(args[i], "-") {
				setPath = args[i]
			}
		}
	}

	if setPath == "" {
		setPath = "benchmarks/sample/set.json"
	}
	if outDir == "" {
		outDir = "benchmark_runs"
	}

	fmt.Printf("  [*] Loading benchmark set: %s\n", setPath)
	set, err := benchmark.LoadSet(setPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [x] %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  [*] %d challenges loaded. Running (timeout %s each, concurrency %d)...\n", len(set.Challenges), timeout, concurrency)

	summary, err := benchmark.Run(context.Background(), set, cfg, benchmark.RunMode{ChallengeTimeout: timeout, Concurrency: concurrency})
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [x] benchmark run failed: %v\n", err)
		os.Exit(1)
	}

	reportPath, err := summary.Write(outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [x] writing report: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n  ✔ Benchmark complete: %d/%d solved (%.1f%%)\n", summary.Solved, summary.Total, summary.SuccessRate)
	fmt.Printf("  ✔ Report: %s\n", reportPath)
}

// runWhitebox handles the `drogonclaw whitebox` subcommand.
//
//	./drogonclaw whitebox -u https://app.example.com -r ./my-repo -o out/
//
// It runs DrogonClaw's autonomous white-box web/API pipeline (source SAST →
// recon → five vuln agents → proof-by-exploitation → Markdown + SARIF report).
func runWhitebox(cfg *config.Manager, args []string) {
	var targetURL, repoPath, outDir, sessionOverride string
	verify := true

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-u", "--url":
			if i+1 < len(args) {
				targetURL = args[i+1]
				i++
			}
		case "-r", "--repo":
			if i+1 < len(args) {
				repoPath = args[i+1]
				i++
			}
		case "-o", "--out":
			if i+1 < len(args) {
				outDir = args[i+1]
				i++
			}
		case "-s", "--session":
			if i+1 < len(args) {
				sessionOverride = args[i+1]
				i++
			}
		case "--no-verify":
			verify = false
		default:
			if targetURL == "" && repoPath == "" && !strings.HasPrefix(args[i], "-") {
				targetURL = args[i]
			}
		}
	}

	if targetURL == "" && repoPath == "" {
		fmt.Fprintln(os.Stderr, "  [x] whitebox requires -u <url> and/or -r <repo>")
		os.Exit(1)
	}

	provider, sb, manifest, err := runStartup(cfg, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [x] Startup failed: %v\n", err)
		os.Exit(1)
	}
	if sb == nil {
		fmt.Fprintln(os.Stderr, "  [x] Sandbox initialization failed")
		os.Exit(1)
	}

	sessionID := sessionOverride
	if sessionID == "" {
		sessionID = fmt.Sprintf("wb%010d", rand.Intn(9000000000)+1000000000)
	}
	// Reusing a session ID reloads its task tree from data/graph_<session>.json,
	// so already-completed phases are skipped (resume).
	graph := memory.NewGraph(sessionID)

	lootDb, err := memory.NewLootDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [!] Loot DB init failed: %v\n", err)
	} else {
		defer lootDb.Close()
	}

	validator := agent.NewEvidenceValidator(provider)
	tools := agent.NewToolRegistry(manifest, sb, validator, lootDb, cfg, graph, provider)

	fmt.Printf("  [*] White-box assessment: url=%s repo=%s verify=%v\n", targetURL, repoPath, verify)

	rep, err := whitebox.Run(context.Background(), whitebox.Config{
		TargetURL: targetURL,
		RepoPath:  repoPath,
		SessionID: sessionID,
		OutDir:    outDir,
		Verify:    verify,
	}, tools, graph, lootDb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [x] whitebox run failed: %v\n", err)
		os.Exit(1)
	}

	path, err := rep.Write(outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [x] writing report: %v\n", err)
		os.Exit(1)
	}

	verified := 0
	for _, f := range rep.Findings {
		if f.Verified {
			verified++
		}
	}
	fmt.Printf("  [+] %d findings (%d verified). Report: %s\n", len(rep.Findings), verified, path)
}

// runHeadlessPrompt executes a single prompt without the TUI interface.
// Supports plain text and structured JSON output for CLI pipeline integration.
func runHeadlessPrompt(orch *agent.Orchestrator, prompt string, outputFormat string, quiet bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	events := make(chan agent.Event, 32)
	go func() {
		_ = orch.Execute(ctx, prompt, events)
	}()

	var finalAnswer strings.Builder
	var executedTools []string

	for ev := range events {
		switch ev.Type {
		case agent.EvToolStart:
			executedTools = append(executedTools, ev.Tool)
			if !quiet && outputFormat != "json" {
				fmt.Fprintf(os.Stderr, "  [*] Executing: %s (%s)\n", ev.Tool, ev.Args)
			}
		case agent.EvToolDone:
			if !quiet && outputFormat != "json" {
				fmt.Fprintf(os.Stderr, "  [✓] Completed: %s\n", ev.Tool)
			}
		case agent.EvToken:
			finalAnswer.WriteString(ev.Content)
			if outputFormat == "text" && !quiet {
				fmt.Print(ev.Content)
			}
		case agent.EvDone:
			if finalAnswer.Len() == 0 {
				finalAnswer.WriteString(ev.Content)
			}
		case agent.EvError:
			if !quiet && outputFormat != "json" {
				fmt.Fprintf(os.Stderr, "  [x] Error: %s\n", ev.Content)
			}
		}
	}

	res := strings.TrimSpace(finalAnswer.String())
	if outputFormat == "json" {
		outObj := map[string]any{
			"prompt":    prompt,
			"response":  res,
			"tools_run": executedTools,
			"session":   orch.SessionID,
		}
		b, _ := json.MarshalIndent(outObj, "", "  ")
		fmt.Println(string(b))
	} else if quiet {
		fmt.Println(res)
	} else if finalAnswer.Len() == 0 {
		fmt.Println(res)
	}
}

// diagnoseProviderError turns a raw ping failure into an actionable message.
func diagnoseProviderError(cfg *config.Manager, err error) error {
	base := fmt.Sprintf("provider %q (model %q, endpoint %s)", cfg.GetProvider(), cfg.GetModel(), cfg.GetBaseURL())
	msg := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "Client.Timeout"):
		return fmt.Errorf("could not reach %s within 20s: %w\n  - check this host can reach the endpoint (e.g. curl -sS %s/models)\n  - if behind a corporate proxy, export HTTP_PROXY/HTTPS_PROXY (or NO_PROXY for the host)\n  - verify DNS resolution", base, err, cfg.GetBaseURL())
	case strings.Contains(msg, "401") || strings.Contains(msg, "403") || strings.Contains(msg, "unauthorized") || strings.Contains(msg, "invalid api key"):
		return fmt.Errorf("auth rejected by %s: %w\n  - re-run ./drogonclaw setup and paste a valid API key", base, err)
	default:
		return fmt.Errorf("provider connection failed for %s: %w", base, err)
	}
}
