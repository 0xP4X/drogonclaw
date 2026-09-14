package agent

import (
	"context"
	"fmt"

	"github.com/0xP4X/drogonclaw-go/internal/memory"
	"github.com/openai/openai-go"
)

// AutoCompactor manages conversation history token usage and compresses
// historical tool outputs into a compact executive memory summary when approaching limits.
type AutoCompactor struct {
	provider *Provider
	graph    *memory.Graph
}

// NewAutoCompactor initializes a compactor for managing context length.
func NewAutoCompactor(p *Provider, g *memory.Graph) *AutoCompactor {
	return &AutoCompactor{
		provider: p,
		graph:    g,
	}
}

// ShouldCompact evaluates whether the message history should be pruned or summarized.
// Triggers when message history exceeds safety threshold (e.g. 24 turns or excessive raw text).
func (c *AutoCompactor) ShouldCompact(history []openai.ChatCompletionMessageParamUnion) bool {
	if len(history) < 16 {
		return false
	}
	return true
}

// Compact summarizes intermediate turns and preserves key loot, verified findings, and objectives.
func (c *AutoCompactor) Compact(ctx context.Context, history []openai.ChatCompletionMessageParamUnion) ([]openai.ChatCompletionMessageParamUnion, string, error) {
	if len(history) <= 6 {
		return history, "", nil
	}

	summaryPrompt := `You are an offensive security state summarizer. Condense the past reconnaissance and exploitation actions into a clean, factual summary:
1. TARGET ASSETS & IDENTIFIERS DISCOVERED: (IPs, domains, endpoints, technologies)
2. PORTS & SERVICES VERIFIED: (Port numbers, service names, banner versions)
3. CREDENTIALS & SENSITIVE DATA: (Usernames, tokens, hashes)
4. EXPLOITATION & VULNERABILITY ATTEMPTS: (What was tested, what succeeded, what failed)
5. CURRENT MISSION OBJECTIVE: (What the operator asked to do next)

Be dense, precise, and omit conversational pleasantries.`

	msgs := []openai.ChatCompletionMessageParamUnion{
		openai.SystemMessage(summaryPrompt),
	}
	// Append the older middle turns
	middleEnd := len(history) - 4
	msgs = append(msgs, history[:middleEnd]...)
	msgs = append(msgs, openai.UserMessage("Summarize the above security engagement progress concisely."))

	summary, err := c.provider.CompleteText(ctx, msgs)
	if err != nil {
		return history, "", fmt.Errorf("compact failed: %w", err)
	}

	// Rebuild history: First user message + System Summary + Recent 4 messages
	newHistory := make([]openai.ChatCompletionMessageParamUnion, 0)
	if len(history) > 0 {
		newHistory = append(newHistory, history[0])
	}
	newHistory = append(newHistory, openai.SystemMessage(fmt.Sprintf("--- COMPACTED ENGAGEMENT SUMMARY ---\n%s\n--- END SUMMARY ---", summary)))
	newHistory = append(newHistory, history[middleEnd:]...)

	return newHistory, summary, nil
}
