package fix

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Planner resolves finding fix_hints against the registry and produces proposals.
type Planner struct {
	registry *Registry
}

// NewPlanner creates a planner with the default registry.
func NewPlanner() *Planner {
	return &Planner{registry: NewRegistry()}
}

// ResolveOptions controls how Resolve behaves.
type ResolveOptions struct {
	FindingID string
	Source    schema.FixSource
	RunID     string
	ReportAge time.Duration
	DebugLog  func(string, ...interface{})
}

// Resolve returns fix proposals for a finding in a report.
func (p *Planner) Resolve(report *schema.Report, opts ResolveOptions) ([]schema.FixProposal, error) {
	if report == nil {
		return nil, fmt.Errorf("report is nil")
	}

	// Find the target finding
	var target *schema.Finding
	for i := range report.Findings {
		if report.Findings[i].ID == opts.FindingID {
			target = &report.Findings[i]
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("finding %q not found in report", opts.FindingID)
	}

	// Build evidence lookup
	evidenceMap := buildEvidenceMap(report)
	findingEvidence := evidenceForFinding(target, evidenceMap)

	var proposals []schema.FixProposal
	for _, hintID := range target.FixHints {
		tmpl, ok := p.registry.Lookup(hintID)
		if !ok {
			if opts.DebugLog != nil {
				opts.DebugLog("skipping template %s: not found in registry", hintID)
			}
			continue
		}
		if !tmpl.IsApplicable() {
			if opts.DebugLog != nil {
				opts.DebugLog("skipping template %s: not applicable on this platform", hintID)
			}
			continue
		}

		// Validate required evidence
		values, missing, err := validateEvidence(tmpl, findingEvidence, report.Repo.Root)
		if err != nil {
			if opts.DebugLog != nil {
				opts.DebugLog("skipping template %s: evidence validation error: %v", hintID, err)
			}
			continue
		}
		if len(missing) > 0 {
			// Evidence incomplete; skip unless manual
			if tmpl.Class != schema.FixManual {
				if opts.DebugLog != nil {
					opts.DebugLog("skipping template %s: missing required evidence: %v", hintID, missing)
				}
				continue
			}
		}

		// Bind template
		boundArgs, boundRollback, err := BindTemplate(tmpl, values)
		if err != nil {
			if opts.DebugLog != nil {
				opts.DebugLog("skipping template %s: bind error: %v", hintID, err)
			}
			continue
		}

		proposal := schema.FixProposal{
			FindingID:        opts.FindingID,
			HintID:           hintID,
			Title:            tmpl.Title,
			Class:            tmpl.Class,
			Bin:              tmpl.Bin,
			Args:             boundArgs,
			Rollback:         boundRollback,
			ConfirmMessage:   tmpl.ConfirmMessage,
			BlockedReason:    tmpl.BlockedReason,
			RequiredEvidence: tmpl.RequiredEvidence,
			Source:           opts.Source,
			RunID:            opts.RunID,
		}

		// Staleness warnings
		if opts.ReportAge > 30*time.Minute {
			proposal.StalenessWarn = fmt.Sprintf("Report is %s old; consider --fresh before applying", opts.ReportAge)
		} else if opts.ReportAge > 5*time.Minute {
			proposal.StalenessWarn = fmt.Sprintf("Report is %s old", opts.ReportAge)
		}

		proposals = append(proposals, proposal)
	}

	// Rank: safe > guarded > manual
	proposals = rankProposals(proposals)
	return proposals, nil
}

// ListAll returns proposals for every finding in a report that has fix_hints.
func (p *Planner) ListAll(report *schema.Report, source schema.FixSource, runID string, reportAge time.Duration) ([]schema.FixProposal, error) {
	if report == nil {
		return nil, fmt.Errorf("report is nil")
	}
	var all []schema.FixProposal
	for _, f := range report.Findings {
		if len(f.FixHints) == 0 {
			continue
		}
		proposals, err := p.Resolve(report, ResolveOptions{
			FindingID: f.ID,
			Source:    source,
			RunID:     runID,
			ReportAge: reportAge,
		})
		if err != nil {
			continue
		}
		all = append(all, proposals...)
	}
	return all, nil
}

func buildEvidenceMap(report *schema.Report) map[string][]schema.Evidence {
	m := make(map[string][]schema.Evidence)
	for _, c := range report.Collectors {
		for _, ev := range c.Evidence {
			m[ev.Source] = append(m[ev.Source], ev)
		}
	}
	return m
}

func evidenceForFinding(finding *schema.Finding, evidenceMap map[string][]schema.Evidence) map[string]string {
	result := make(map[string]string)
	// Include finding's own evidence
	for _, ev := range finding.Evidence {
		result[ev.Source] = ev.Value
	}
	// Also pull from report-level evidence map for cross-collector lookups
	for k, v := range evidenceMap {
		if _, ok := result[k]; !ok && len(v) > 0 {
			result[k] = v[0].Value
		}
	}
	return result
}

func validateEvidence(tmpl Template, evidence map[string]string, repoRoot string) (values map[string]string, missing []string, err error) {
	values = make(map[string]string)
	if repoRoot == "" {
		repoRoot = "."
	}
	if strings.HasPrefix(repoRoot, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			if repoRoot == "~" {
				repoRoot = home
			} else if strings.HasPrefix(repoRoot, "~/") {
				repoRoot = filepath.Join(home, strings.TrimPrefix(repoRoot, "~/"))
			}
		}
	}
	if !filepath.IsAbs(repoRoot) {
		abs, err := filepath.Abs(repoRoot)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to make repo root absolute: %w", err)
		}
		repoRoot = abs
	}
	values["repo_root"] = filepath.Clean(repoRoot)
	for _, req := range tmpl.RequiredEvidence {
		if req == "compose_status" {
			service, status, ok := composeStatusEvidence(evidence)
			if !ok {
				missing = append(missing, req)
				continue
			}
			values["service"] = service
			values["status"] = status
			continue
		}
		val, ok := evidence[req]
		if !ok || val == "" {
			missing = append(missing, req)
			continue
		}
		// Type-specific validation and binding
		switch req {
		case "host_script_not_executable":
			p, err := ValidatePath(repoRoot, val)
			if err != nil {
				return nil, nil, err
			}
			values["path"] = p
		case "git_tracked_env", "git_env_exists":
			// These are boolean/status evidence; no typed binding needed for gitignore-env
			values["env"] = val
		case "compose_host_port", "host_listen_port":
			portStr := val
			if strings.Contains(val, ":") {
				parts := strings.Split(val, ":")
				portStr = parts[len(parts)-1]
			}
			p, err := ValidatePort(portStr)
			if err != nil {
				return nil, nil, err
			}
			values["port"] = strconv.Itoa(p)
		case "missing_keys":
			parts := strings.Split(val, ",")
			var valid []string
			for _, k := range parts {
				k = strings.TrimSpace(k)
				if _, err := ValidateEnvKey(k); err == nil {
					valid = append(valid, k)
				}
			}
			values["keys"] = strings.Join(valid, " ")
		case "host_disk_free_bytes", "host_disk_free_pct":
			// No typed binding needed for manual warning
			values["disk"] = val
		case "docker_socket_permission_denied":
			values["docker"] = val
		default:
			values["value"] = val
		}
	}
	return values, missing, nil
}

func composeStatusEvidence(evidence map[string]string) (service string, status string, ok bool) {
	for source, value := range evidence {
		if !strings.HasPrefix(source, "compose_service_") || !strings.HasSuffix(source, "_status") {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(source, "compose_service_"), "_status")
		validName, err := ValidateServiceName(name)
		if err != nil {
			continue
		}
		switch value {
		case "exited", "dead", "restarting":
			return validName, value, true
		}
	}
	return "", "", false
}

func rankProposals(proposals []schema.FixProposal) []schema.FixProposal {
	order := map[schema.FixClass]int{
		schema.FixSafe:    0,
		schema.FixGuarded: 1,
		schema.FixManual:  2,
		schema.FixBlocked: 3,
	}
	// Simple insertion sort by class priority
	for i := 1; i < len(proposals); i++ {
		j := i
		for j > 0 && order[proposals[j].Class] < order[proposals[j-1].Class] {
			proposals[j], proposals[j-1] = proposals[j-1], proposals[j]
			j--
		}
	}
	return proposals
}
