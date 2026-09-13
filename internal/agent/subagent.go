package agent

// SubagentManager enables parallel execution of independent recon/exploitation
// tasks. Inspired by Hermes Agent's subagent delegation which "spawns isolated
// subagents for parallel workstreams" with "zero context-cost turns."
//
// Instead of running nmap → subdomain_enum → web_recon sequentially (taking
// 10+ minutes), the subagent manager runs them in parallel (taking 3-4 minutes).
//
// Usage:
//
//	sm := NewSubagentManager(provider, tools, maxConcurrent)
//	results := sm.ExecuteParallel(ctx, tasks, events)
//	for _, r := range results {
//	    // Merge results into main context
//	}

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/openai/openai-go"
)

// SubagentTask represents a single unit of work to be executed by a subagent.
type SubagentTask struct {
	ID          string         // Unique identifier for this task
	Name        string         // Human-readable name (e.g., "Port Scan")
	Tool        string         // Tool to execute (e.g., "run_nmap")
	Args        map[string]any // Tool arguments
	Context     string         // Additional context for the subagent
	Priority    int            // Higher = runs first (default: 0)
	DependsOn   []string       // IDs of tasks that must complete first
}

// SubagentResult holds the outcome of a subagent execution.
type SubagentResult struct {
	TaskID   string
	Tool     string
	Output   string
	Duration time.Duration
	Error    error
}

// SubagentManager orchestrates parallel tool execution.
type SubagentManager struct {
	provider *Provider
	tools    *ToolRegistry
	maxConc  int
}

// NewSubagentManager creates a manager with a concurrency limit.
func NewSubagentManager(provider *Provider, tools *ToolRegistry, maxConcurrent int) *SubagentManager {
	if maxConcurrent <= 0 {
		maxConcurrent = 5
	}
	return &SubagentManager{
		provider: provider,
		tools:    tools,
		maxConc:  maxConcurrent,
	}
}

// SpawnSubagent executes a single dedicated subagent task. If events is nil, events are ignored.
func (sm *SubagentManager) SpawnSubagent(ctx context.Context, task SubagentTask, events chan<- Event) SubagentResult {
	if events == nil {
		ch := make(chan Event, 20)
		go func() {
			for range ch {
			}
		}()
		events = ch
	}

	start := time.Now()
	events <- Event{
		Type:    EvStatus,
		Content: fmt.Sprintf("[SUBAGENT:%s] Spawning subagent: %s...", task.ID, task.Name),
	}

	var output string
	var err error

	if task.Tool != "" {
		output = sm.tools.Execute(ctx, task.Tool, marshalArgs(task.Args))
	} else if task.Context != "" && sm.provider != nil {
		subPrompt := fmt.Sprintf("You are a specialized pentesting subagent (%s).\nObjective: %s\nTarget context: %s\nAnalyze thoroughly and return your concise technical findings.", task.Name, task.Context, marshalArgs(task.Args))
		messages := []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage(subPrompt),
		}
		resp, completeErr := sm.provider.CompleteFast(ctx, messages, nil)
		if completeErr != nil {
			resp, completeErr = sm.provider.Complete(ctx, messages, nil)
		}
		if completeErr != nil {
			output = fmt.Sprintf("[Subagent Error] %v", completeErr)
			err = completeErr
		} else {
			output = resp.Message.Content
		}
	} else {
		output = fmt.Sprintf("[Subagent %s] No tool or prompt specified", task.ID)
		err = fmt.Errorf("no tool or prompt specified")
	}

	duration := time.Since(start)
	events <- Event{
		Type:    EvStatus,
		Content: fmt.Sprintf("[SUBAGENT:%s] Completed %s in %s", task.ID, task.Name, duration.Round(time.Second)),
	}

	return SubagentResult{
		TaskID:   task.ID,
		Tool:     task.Tool,
		Output:   output,
		Duration: duration,
		Error:    err,
	}
}

// ExecuteParallel runs independent tasks concurrently, respecting dependencies.
// Returns results in the order they were submitted.
func (sm *SubagentManager) ExecuteParallel(ctx context.Context, tasks []SubagentTask, events chan<- Event) []SubagentResult {
	if len(tasks) == 0 {
		return nil
	}

	// Build dependency graph
	ready := make([]SubagentTask, 0)
	waiting := make([]SubagentTask, 0)
	for _, t := range tasks {
		if len(t.DependsOn) == 0 {
			ready = append(ready, t)
		} else {
			waiting = append(waiting, t)
		}
	}

	results := make([]SubagentResult, len(tasks))
	resultIndex := make(map[string]int)
	for i, t := range tasks {
		resultIndex[t.ID] = i
	}

	// Execute in waves: first the independent tasks, then tasks whose deps are done
	completed := make(map[string]bool)
	var mu sync.Mutex

	for len(waiting) > 0 || len(ready) > 0 {
		if len(ready) == 0 {
			// No ready tasks but waiting tasks exist — this means circular dependency
			// Break the cycle by taking the first waiting task
			if len(waiting) > 0 {
				ready = append(ready, waiting[0])
				waiting = waiting[1:]
			}
		}

		// Run ready tasks with concurrency limit
		var wg sync.WaitGroup
		sem := make(chan struct{}, sm.maxConc)

		for _, task := range ready {
			wg.Add(1)
			sem <- struct{}{}
			go func(t SubagentTask) {
				defer wg.Done()
				defer func() { <-sem }()

				events <- Event{
					Type:    EvStatus,
					Content: fmt.Sprintf("[PARALLEL] Starting %s...", t.Name),
				}

				start := time.Now()
				output := sm.tools.Execute(ctx, t.Tool, marshalArgs(t.Args))
				duration := time.Since(start)

				mu.Lock()
				completed[t.ID] = true
				results[resultIndex[t.ID]] = SubagentResult{
					TaskID:   t.ID,
					Tool:     t.Tool,
					Output:   output,
					Duration: duration,
				}
				mu.Unlock()

				events <- Event{
					Type:    EvStatus,
					Content: fmt.Sprintf("[PARALLEL] Completed %s in %s", t.Name, duration.Round(time.Second)),
				}
			}(task)
		}

		wg.Wait()

		// Find newly ready tasks
		ready = ready[:0]
		remaining := make([]SubagentTask, 0, len(waiting))
		for _, t := range waiting {
			allDepsDone := true
			for _, dep := range t.DependsOn {
				if !completed[dep] {
					allDepsDone = false
					break
				}
			}
			if allDepsDone {
				ready = append(ready, t)
			} else {
				remaining = append(remaining, t)
			}
		}
		waiting = remaining
	}

	return results
}

// FormatResultsForLLM formats parallel results into a summary for the main LLM context.
func FormatResultsForLLM(results []SubagentResult) string {
	if len(results) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("PARALLEL EXECUTION RESULTS (%d tasks completed):\n\n", len(results)))

	for _, r := range results {
		status := "SUCCESS"
		if r.Error != nil {
			status = "FAILED"
		}
		sb.WriteString(fmt.Sprintf("─── %s [%s] (%s) ───\n", r.TaskID, status, r.Duration.Round(time.Second)))
		sb.WriteString(r.Output)
		sb.WriteString("\n\n")
	}

	return sb.String()
}

// MergeResults extracts findings from parallel results and merges them into
// a single context block for the main agent.
func MergeResults(results []SubagentResult) string {
	var findings []string
	for _, r := range results {
		// Extract port findings
		if strings.Contains(r.Output, "open") {
			findings = append(findings, extractPortFindings(r.Output)...)
		}
		// Extract service findings
		if strings.Contains(r.Output, "http") || strings.Contains(r.Output, "Service") {
			findings = append(findings, extractServiceFindings(r.Output)...)
		}
	}

	if len(findings) == 0 {
		return ""
	}

	return fmt.Sprintf("MERGED FINDINGS from parallel execution:\n%s",
		strings.Join(findings, "\n"))
}

func extractPortFindings(output string) []string {
	var findings []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "open") || strings.Contains(line, "filtered") {
			findings = append(findings, "PORT: "+strings.TrimSpace(line))
		}
	}
	return findings
}

func extractServiceFindings(output string) []string {
	var findings []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Service:") || strings.Contains(line, "http/") {
			findings = append(findings, "SERVICE: "+strings.TrimSpace(line))
		}
	}
	return findings
}

func marshalArgs(args map[string]any) string {
	if args == nil {
		return "{}"
	}
	b, err := json.Marshal(args)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ── Parallel Recon Preset ────────────────────────────────────────────────────

// StandardReconTasks returns a preset of parallel recon tasks for a target.
// This is the most common parallel pattern: port scan + subdomain enum + web recon.
func StandardReconTasks(target string) []SubagentTask {
	return []SubagentTask{
		{
			ID:       "port_scan",
			Name:     "Port Scan",
			Tool:     "run_nmap",
			Args:     map[string]any{"target": target, "mode": "quick"},
			Priority: 10,
		},
		{
			ID:       "subdomain_enum",
			Name:     "Subdomain Enumeration",
			Tool:     "run_subfinder",
			Args:     map[string]any{"target": target},
			Priority: 10,
		},
		{
			ID:       "web_recon",
			Name:     "Web Reconnaissance",
			Tool:     "run_httpx",
			Args:     map[string]any{"target": target},
			Priority: 5,
		},
	}
}

// FullWebReconTasks returns parallel tasks for comprehensive web app testing.
func FullWebReconTasks(target string) []SubagentTask {
	return []SubagentTask{
		{
			ID:       "port_scan",
			Name:     "Port Scan",
			Tool:     "run_nmap",
			Args:     map[string]any{"target": target, "mode": "full"},
			Priority: 10,
		},
		{
			ID:       "subdomain_enum",
			Name:     "Subdomain Enumeration",
			Tool:     "run_subfinder",
			Args:     map[string]any{"target": target},
			Priority: 10,
		},
		{
			ID:       "web_probe",
			Name:     "Web Probing",
			Tool:     "run_httpx",
			Args:     map[string]any{"target": target},
			Priority: 5,
			DependsOn: []string{"subdomain_enum"},
		},
		{
			ID:       "dir_bruteforce",
			Name:     "Directory Bruteforce",
			Tool:     "run_gobuster",
			Args:     map[string]any{"target": target, "mode": "dir"},
			Priority: 5,
			DependsOn: []string{"port_scan"},
		},
		{
			ID:       "vuln_scan",
			Name:     "Vulnerability Scan",
			Tool:     "run_nuclei",
			Args:     map[string]any{"target": target, "severity": "critical,high"},
			Priority: 5,
			DependsOn: []string{"port_scan"},
		},
	}
}

// CloudTasks returns parallel tasks for cloud infrastructure testing.
func CloudTasks(target string) []SubagentTask {
	return []SubagentTask{
		{
			ID:       "cert_transparency",
			Name:     "Certificate Transparency",
			Tool:     "osint_certs",
			Args:     map[string]any{"target": target},
			Priority: 10,
		},
		{
			ID:       "dns_enumeration",
			Name:     "DNS Enumeration",
			Tool:     "run_subfinder",
			Args:     map[string]any{"target": target},
			Priority: 10,
		},
		{
			ID:       "port_scan",
			Name:     "Port Scan",
			Tool:     "run_nmap",
			Args:     map[string]any{"target": target, "mode": "quick"},
			Priority: 5,
		},
	}
}
