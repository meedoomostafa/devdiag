package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

const (
	SchemaVersion  = "0.1"
	TrustUntrusted = "untrusted"
)

type Redactor func(string) string

type Input struct {
	Kind    string `json:"kind"`
	Path    string `json:"path,omitempty"`
	Content string `json:"-"`
}

type ContextRequest struct {
	Root   string
	Inputs []Input
	Redact Redactor
}

type Context struct {
	SchemaVersion     string         `json:"schema_version"`
	GeneratedAt       string         `json:"generated_at"`
	Root              string         `json:"root"`
	Inputs            []ContextInput `json:"inputs"`
	Findings          []Finding      `json:"findings,omitempty"`
	ProviderRequested string         `json:"provider_requested,omitempty"`
	ProviderUsed      string         `json:"provider_used,omitempty"`
	Model             string         `json:"model,omitempty"`
	Explanation       string         `json:"explanation,omitempty"`
	ProviderFallback  bool           `json:"provider_fallback,omitempty"`
	ProviderNotes     []string       `json:"provider_notes,omitempty"`
}

type ContextInput struct {
	Kind    string `json:"kind"`
	Path    string `json:"path,omitempty"`
	Trust   string `json:"trust"`
	SHA256  string `json:"sha256,omitempty"`
	Preview string `json:"preview,omitempty"`
}

type Finding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Trust    string `json:"trust"`
	Excerpt  string `json:"excerpt,omitempty"`
	Message  string `json:"message"`
}

func BuildContext(req ContextRequest) Context {
	redact := req.Redact
	if redact == nil {
		redact = func(s string) string { return s }
	}
	ctx := Context{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Root:          req.Root,
	}
	for _, input := range req.Inputs {
		preview := truncate(redact(input.Content), 4096)
		sum := sha256.Sum256([]byte(input.Content))
		ctx.Inputs = append(ctx.Inputs, ContextInput{
			Kind:    input.Kind,
			Path:    input.Path,
			Trust:   TrustUntrusted,
			SHA256:  hex.EncodeToString(sum[:]),
			Preview: preview,
		})
		ctx.Findings = append(ctx.Findings, ClassifyPromptInjection(preview)...)
	}
	return ctx
}

func ClassifyPromptInjection(text string) []Finding {
	lower := strings.ToLower(text)
	var findings []Finding
	if containsAny(lower, []string{
		"ignore previous instructions",
		"disregard previous instructions",
		"forget previous instructions",
		"system prompt",
		"developer message",
	}) {
		findings = append(findings, Finding{
			ID:       "A-INJECTION-001",
			Title:    "Possible instruction injection in untrusted content",
			Severity: "medium",
			Trust:    TrustUntrusted,
			Excerpt:  excerpt(text),
			Message:  "Untrusted content appears to contain instructions directed at an AI agent.",
		})
	}
	if containsAny(lower, []string{
		"print all secrets",
		"send secrets",
		"exfiltrate",
		"api key",
		"private key",
		"environment variables",
		"env vars",
	}) {
		findings = append(findings, Finding{
			ID:       "A-SECRET-EXFIL-001",
			Title:    "Possible secret exfiltration request in untrusted content",
			Severity: "high",
			Trust:    TrustUntrusted,
			Excerpt:  excerpt(text),
			Message:  "Untrusted content appears to request secret or environment disclosure.",
		})
	}
	return findings
}

func containsAny(text string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func excerpt(text string) string {
	text = strings.TrimSpace(text)
	return truncate(text, 240)
}

func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "\n... [truncated]"
}
