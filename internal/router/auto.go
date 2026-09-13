package router

import (
	"context"
	"sync"
)

// AutoRouter tries 9router.ai first, then falls back to local rules.
// This is the recommended mode for most operators.
type AutoRouter struct {
	primary  Router
	fallback Router
	mu       sync.RWMutex
	stats    *RoutingStats
}

// NewAutoRouter creates an auto router with the given 9router API key.
// If apiKey is empty it degenerates to a pure local router.
func NewAutoRouter(apiKey string, rules []RoutingRule) *AutoRouter {
	if len(rules) == 0 {
		rules = DefaultRules
	}
	var primary Router
	if apiKey != "" {
		primary = NewNineRouterClient(apiKey)
	}
	return &AutoRouter{
		primary:  primary,
		fallback: NewLocalRouter(rules),
		stats: &RoutingStats{
			ProviderCounts: make(map[string]int),
			TaskTypeCounts: make(map[TaskType]int),
		},
	}
}

// Route tries the primary (9router.ai) first, then local fallback.
func (a *AutoRouter) Route(ctx context.Context, taskType TaskType, prompt string) (*RouteDecision, error) {
	a.mu.Lock()
	a.stats.TotalRequests++
	a.stats.TaskTypeCounts[taskType]++
	a.mu.Unlock()

	// Try primary if available
	if a.primary != nil && a.primary.IsAvailable() {
		decision, err := a.primary.Route(ctx, taskType, prompt)
		if err == nil && decision != nil {
			a.mu.Lock()
			a.stats.SuccessfulRoutes++
			a.stats.ProviderCounts[decision.Provider]++
			a.mu.Unlock()
			return decision, nil
		}
		// Primary failed — fall through to local
	}

	// Fallback to local router
	decision, err := a.fallback.Route(ctx, taskType, prompt)
	a.mu.Lock()
	if err == nil && decision != nil {
		a.stats.SuccessfulRoutes++
		a.stats.ProviderCounts[decision.Provider]++
	} else {
		a.stats.FailedRoutes++
	}
	a.mu.Unlock()
	return decision, err
}

// GetStats returns a copy of routing statistics.
func (a *AutoRouter) GetStats() *RoutingStats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	c := *a.stats
	c.ProviderCounts = make(map[string]int)
	c.TaskTypeCounts = make(map[TaskType]int)
	for k, v := range a.stats.ProviderCounts {
		c.ProviderCounts[k] = v
	}
	for k, v := range a.stats.TaskTypeCounts {
		c.TaskTypeCounts[k] = v
	}
	return &c
}

// IsAvailable reports whether at least one underlying router is available.
func (a *AutoRouter) IsAvailable() bool {
	if a.primary != nil && a.primary.IsAvailable() {
		return true
	}
	return a.fallback.IsAvailable()
}

// ClassifyTaskType heuristically maps a raw user prompt to a TaskType.
// Used by the orchestrator to select routing rules without LLM help.
func ClassifyTaskType(prompt string) TaskType {
	lower := toLower(prompt)
	switch {
	case containsAny(lower, []string{"exploit", "cve-", "priv esc", "privilege escalation", "payload", "shell", "rce", "sqli", "xss exploit"}):
		return TaskExploitation
	case containsAny(lower, []string{"scan", "nmap", "recon", "enumerate", "subdomain", "port ", "nuclei", "gobuster", "ffuf", "osint", "github", "shodan", "virustotal", "whois"}):
		return TaskRecon
	case containsAny(lower, []string{"report", "summary", "document findings", "executive summary"}):
		return TaskReporting
	case containsAny(lower, []string{"analyze", "analysis", "binary", "reverse engineer", "forensics"}):
		return TaskAnalysis
	case containsAny(lower, []string{"plan", "mission", "workflow", "attack chain", "methodology"}):
		return TaskPlanning
	default:
		// Short prompts are usually chat; longer ones need planning
		if wordCount(prompt) <= 5 {
			return TaskChat
		}
		return TaskPlanning
	}
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if len(sub) == 0 {
			continue
		}
		if indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	if len(sub) == 0 {
		return 0
	}
	if len(s) < len(sub) {
		return -1
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func wordCount(s string) int {
	n := 0
	inWord := false
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' || s[i] == '\n' {
			inWord = false
		} else if !inWord {
			inWord = true
			n++
		}
	}
	return n
}
