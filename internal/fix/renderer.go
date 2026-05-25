package fix

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// ProposalRenderer renders fix proposals to a writer.
type ProposalRenderer interface {
	Render(proposals []schema.FixProposal, w io.Writer) error
}

// HumanRenderer renders proposals for human consumption.
type HumanRenderer struct{}

func (r *HumanRenderer) Render(proposals []schema.FixProposal, w io.Writer) error {
	if len(proposals) == 0 {
		_, _ = fmt.Fprintln(w, "No fix proposals available.")
		return nil
	}

	_, _ = fmt.Fprintf(w, "Fix proposals (%d):\n\n", len(proposals))

	byClass := groupByClass(proposals)
	for _, class := range []schema.FixClass{schema.FixSafe, schema.FixGuarded, schema.FixManual, schema.FixBlocked} {
		items := byClass[class]
		if len(items) == 0 {
			continue
		}
		_, _ = fmt.Fprintf(w, "[%s]\n", strings.ToUpper(string(class)))
		for _, p := range items {
			_, _ = fmt.Fprintf(w, "  %s: %s\n", p.HintID, p.Title)
			if p.Bin != "" || len(p.Args) > 0 {
				_, _ = fmt.Fprintf(w, "    Command: %s %s\n", p.Bin, strings.Join(p.Args, " "))
			}
			if len(p.Rollback) > 0 {
				_, _ = fmt.Fprintf(w, "    Rollback: %s\n", strings.Join(p.Rollback, " "))
			}
			if p.ConfirmMessage != "" {
				_, _ = fmt.Fprintf(w, "    Warning: %s\n", p.ConfirmMessage)
			}
			if p.BlockedReason != "" {
				_, _ = fmt.Fprintf(w, "    Blocked: %s\n", p.BlockedReason)
			}
			if p.StalenessWarn != "" {
				_, _ = fmt.Fprintf(w, "    Staleness: %s\n", p.StalenessWarn)
			}
			_, _ = fmt.Fprintf(w, "    Source: %s", p.Source)
			if p.RunID != "" {
				_, _ = fmt.Fprintf(w, " (run_id=%s)", p.RunID)
			}
			_, _ = fmt.Fprintln(w)
			_, _ = fmt.Fprintln(w)
		}
	}
	return nil
}

// JSONRenderer renders proposals as a JSON array.
type JSONRenderer struct{}

func (r *JSONRenderer) Render(proposals []schema.FixProposal, w io.Writer) error {
	if proposals == nil {
		proposals = []schema.FixProposal{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(proposals)
}

// NDJSONRenderer renders proposals as newline-delimited JSON.
type NDJSONRenderer struct{}

func (r *NDJSONRenderer) Render(proposals []schema.FixProposal, w io.Writer) error {
	for _, p := range proposals {
		data, err := json.Marshal(p)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, string(data)); err != nil {
			return err
		}
	}
	return nil
}

// MarkdownRenderer renders proposals as a markdown checklist.
type MarkdownRenderer struct{}

func (r *MarkdownRenderer) Render(proposals []schema.FixProposal, w io.Writer) error {
	_, _ = fmt.Fprintf(w, "# Fix Proposals (%d)\n\n", len(proposals))
	for _, p := range proposals {
		check := "- [ ]"
		if p.Class == schema.FixBlocked {
			check = "- [x]"
		}
		_, _ = fmt.Fprintf(w, "%s **%s** — %s (%s)\n", check, p.HintID, p.Title, p.Class)
		if p.Bin != "" || len(p.Args) > 0 {
			_, _ = fmt.Fprintf(w, "  ```bash\n  %s %s\n  ```\n", p.Bin, strings.Join(p.Args, " "))
		}
		if len(p.Rollback) > 0 {
			_, _ = fmt.Fprintf(w, "  Rollback: `%s`\n", strings.Join(p.Rollback, " "))
		}
		if p.ConfirmMessage != "" {
			_, _ = fmt.Fprintf(w, "  ⚠️ %s\n", p.ConfirmMessage)
		}
		if p.BlockedReason != "" {
			_, _ = fmt.Fprintf(w, "  🚫 Blocked: %s\n", p.BlockedReason)
		}
		if p.StalenessWarn != "" {
			_, _ = fmt.Fprintf(w, "  ⏱️ %s\n", p.StalenessWarn)
		}
		_, _ = fmt.Fprintf(w, "  Source: `%s` (run_id=%s)\n\n", p.Source, p.RunID)
	}
	return nil
}

func groupByClass(proposals []schema.FixProposal) map[schema.FixClass][]schema.FixProposal {
	m := make(map[schema.FixClass][]schema.FixProposal)
	for _, p := range proposals {
		m[p.Class] = append(m[p.Class], p)
	}
	return m
}
