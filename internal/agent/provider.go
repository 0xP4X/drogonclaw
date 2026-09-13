package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/0xP4X/drogonclaw-go/internal/config"
	"github.com/0xP4X/drogonclaw-go/internal/memory"
	"github.com/0xP4X/drogonclaw-go/internal/opsec"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
)

// Provider wraps the OpenAI-compatible client for all LLM providers.
type Provider struct {
	client    *openai.Client
	model     string
	fastModel string
	onUsage   func(model string, prompt, completion int64)
}

var providerXMLTagRegex = regexp.MustCompile(`(?s)<environment_details>.*?</environment_details>|<[^>]+>`)

func stripProviderXMLTags(s string) string {
	return providerXMLTagRegex.ReplaceAllString(s, "")
}

// NewProvider constructs the LLM client, pointing to the correct provider base URL.
func NewProvider(cfg *config.Manager) *Provider {
	p := &Provider{model: cfg.GetModel(), fastModel: cfg.GetFastModel()}

	opts := []option.RequestOption{
		option.WithAPIKey(cfg.GetAPIKey()),
		option.WithBaseURL(cfg.GetBaseURL()),
	}

	// OpenRouter requires these headers for ranking/analytics
	if cfg.GetProvider() == "openrouter" {
		opts = append(opts,
			option.WithHeader("HTTP-Referer", "https://drogonclaw.xyz"),
			option.WithHeader("X-Title", "DrogonClaw"),
		)
	}

	client := openai.NewClient(opts...)
	p.client = &client
	return p
}

// SetUsageCallback registers a hook that fires after every successful LLM
// call with the model name and token counts. Used by internal/billing to
// track session cost without coupling Provider to a specific billing impl.
func (p *Provider) SetUsageCallback(fn func(model string, prompt, completion int64)) {
	p.onUsage = fn
}

// GetModel returns the model name being used by this provider.
func (p *Provider) GetModel() string {
	return p.model
}

func (p *Provider) recordUsage(model string, prompt, completion int64) {
	if p.onUsage != nil {
		p.onUsage(model, prompt, completion)
	}
}

// CompletionResponse from the LLM.
type CompletionResponse struct {
	Message   openai.ChatCompletionMessage
	ToolCalls []openai.ChatCompletionMessageToolCall
}

// Complete sends messages to the LLM and returns the response.
// Non-streaming: used during tool-calling loops where we need the full response.
func (p *Provider) Complete(ctx context.Context, messages []openai.ChatCompletionMessageParamUnion, tools []openai.ChatCompletionToolParam) (*CompletionResponse, error) {
	return p.complete(ctx, p.model, messages, tools)
}

// CompleteFast sends messages to the LLM using the fast/cheap tier when one is
// configured; otherwise it falls back to the primary model. It is intended for
// high-volume, low-stakes turns (parsing recon/scan output) where latency and
// cost dominate over reasoning depth.
func (p *Provider) CompleteFast(ctx context.Context, messages []openai.ChatCompletionMessageParamUnion, tools []openai.ChatCompletionToolParam) (*CompletionResponse, error) {
	return p.complete(ctx, p.fastModel, messages, tools)
}

// HasFast reports whether a distinct fast/cheap model tier is configured.
func (p *Provider) HasFast() bool {
	return p.fastModel != "" && p.fastModel != p.model
}

func (p *Provider) complete(ctx context.Context, model string, messages []openai.ChatCompletionMessageParamUnion, tools []openai.ChatCompletionToolParam) (*CompletionResponse, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		params := openai.ChatCompletionNewParams{
			Model:    model,
			Messages: messages,
		}
		if len(tools) > 0 {
			params.Tools = tools
		}

		resp, err := p.client.Chat.Completions.New(ctx, params)
		if err == nil {
			if len(resp.Choices) == 0 {
				return nil, fmt.Errorf("LLM returned no choices")
			}
			choice := resp.Choices[0]
			if choice.Message.Content != "" {
				choice.Message.Content = stripProviderXMLTags(choice.Message.Content)
			}
			if resp.Usage.TotalTokens > 0 {
				p.recordUsage(model, resp.Usage.PromptTokens, resp.Usage.CompletionTokens)
			}
			return &CompletionResponse{
				Message:   choice.Message,
				ToolCalls: choice.Message.ToolCalls,
			}, nil
		}

		lastErr = err
		if !isRetryableLLMError(err) || attempt == 2 {
			break
		}
		if err := sleepWithContext(ctx, retryBackoff(attempt)); err != nil {
			return nil, err
		}
	}

	if lastErr != nil && strings.Contains(strings.ToLower(lastErr.Error()), "404") {
		return nil, fmt.Errorf("LLM completion failed after retries: %w — check AI_PROVIDER/AI_MODEL via /setup or /config (current model: %s)", lastErr, p.model)
	}
	return nil, fmt.Errorf("LLM completion failed after retries: %w", lastErr)
}

// CompleteText is a convenience function that sends messages and returns just the string content.
func (p *Provider) CompleteText(ctx context.Context, messages []openai.ChatCompletionMessageParamUnion) (string, error) {
	resp, err := p.Complete(ctx, messages, nil)
	if err != nil {
		return "", err
	}
	return stripProviderXMLTags(resp.Message.Content), nil
}

// StreamFinal streams the final text response (no tools) token by token.
func (p *Provider) StreamFinal(ctx context.Context, messages []openai.ChatCompletionMessageParamUnion, onToken func(string)) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		stream := p.client.Chat.Completions.NewStreaming(ctx, openai.ChatCompletionNewParams{
			Model:    p.model,
			Messages: messages,
		})

		var sb strings.Builder
		for stream.Next() {
			chunk := stream.Current()
			if len(chunk.Choices) > 0 {
				delta := chunk.Choices[0].Delta.Content
				if delta != "" {
					clean := stripProviderXMLTags(delta)
					sb.WriteString(clean)
					onToken(clean)
				}
			}
		}
		if err := stream.Err(); err != nil {
			lastErr = err
			if !isRetryableLLMError(err) || attempt == 2 || sb.Len() > 0 {
				return sb.String(), fmt.Errorf("stream error: %w", err)
			}
			if err := sleepWithContext(ctx, retryBackoff(attempt)); err != nil {
				return sb.String(), err
			}
			continue
		}
		if last := stream.Current(); last.Usage.TotalTokens > 0 {
			p.recordUsage(p.model, last.Usage.PromptTokens, last.Usage.CompletionTokens)
		}
		return sb.String(), nil
	}
	return "", fmt.Errorf("stream error after retries: %w", lastErr)
}

// Ping tests connectivity to the LLM provider.
func (p *Provider) Ping(ctx context.Context) error {
	// Ping the models endpoint rather than generating a completion
	// This avoids 504 timeouts on cold models (e.g. NVIDIA NIM or Ollama)
	_, err := p.client.Models.List(ctx)
	if err != nil {
		// Fallback to chat completion ping if the provider doesn't support /models
		_, fallbackErr := p.client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
			Model: p.model,
			Messages: []openai.ChatCompletionMessageParamUnion{
				openai.UserMessage("ping"),
			},
			MaxTokens: openai.Int(1),
		})
		return fallbackErr
	}
	return nil
}

// BuildMessages constructs the initial message array from history + new user message.
// BuildMessages assembles the message list for one LLM call. memoryContext, if
// non-empty, is appended as a second system message so the agent can see the
// current state of its memory graph (entities/links) on every turn. It is kept
// separate from systemPrompt so persona/stealth overrides applied via
// UpdateSystemPrompt are not clobbered.
func BuildMessages(systemPrompt string, memoryContext string, history []openai.ChatCompletionMessageParamUnion, userMsg string) []openai.ChatCompletionMessageParamUnion {
	msgs := []openai.ChatCompletionMessageParamUnion{
		openai.SystemMessage(systemPrompt),
	}
	if memoryContext != "" {
		msgs = append(msgs, openai.SystemMessage(memoryContext))
	}
	msgs = append(msgs, history...)
	msgs = append(msgs, openai.UserMessage(userMsg))
	return msgs
}

// IsChatOnly returns true if the message is purely conversational and needs no tools.
// It is intentionally conservative: when in doubt, the agent should use tools so the
// LLM can decide at runtime rather than being blocked here.
func IsChatOnly(msg string, graph *memory.Graph, opsecMgr *opsec.Manager) bool {
	lower := strings.ToLower(strings.TrimSpace(msg))

	// Never treat actionable OSINT / tool intents as chat, even if prefixed with a greeting.
	// "hi, check my github" must go through Execute, not ExecuteChat.
	actionableKeywords := []string{
		"github", "osint", "shodan", "virustotal", "whois", "check my",
		"search my", "lookup", "profile_target", "scan", "nmap", "nuclei",
		"gobuster", "ffuf", "sqlmap", "subfinder", "httpx", "who am i",
		"tell me about", "projects", "repos", "repositories",
	}
	for _, kw := range actionableKeywords {
		if strings.Contains(lower, kw) {
			return false
		}
	}

	// Obvious greetings / small talk — no tools needed.
	greetings := []string{
		"hi", "hello", "hey", "greetings", "good morning", "good afternoon",
		"good evening", "howdy", "yo", "sup", "what's up", "whats up",
		"nice to meet you", "pleasure", "thanks", "thank you", "thx",
	}
	for _, g := range greetings {
		if lower == g {
			return true
		}
	}

	// Short pleasantries with no actionable content.
	if len(strings.Fields(lower)) <= 2 {
		for _, g := range greetings {
			if strings.HasPrefix(lower, g) {
				return true
			}
		}
	}

	// Anything with a target, a tool keyword, or a question about a system
	// should go through the full agent so it can use tools.
	return false
}

func retryBackoff(attempt int) time.Duration {
	switch attempt {
	case 0:
		return 350 * time.Millisecond
	case 1:
		return 900 * time.Millisecond
	default:
		return 1500 * time.Millisecond
	}
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func isRetryableLLMError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"),
		strings.Contains(msg, "temporarily"),
		strings.Contains(msg, "try again"),
		strings.Contains(msg, "eof"),
		strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "broken pipe"),
		strings.Contains(msg, "503"),
		strings.Contains(msg, "502"),
		strings.Contains(msg, "504"):
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	if _, ok := err.(*url.Error); ok {
		return true
	}
	return false
}
