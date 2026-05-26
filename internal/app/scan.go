package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/collectors"
	"github.com/meedoomostafa/devdiag/internal/collectors/cache"
	"github.com/meedoomostafa/devdiag/internal/collectors/ci"
	"github.com/meedoomostafa/devdiag/internal/collectors/compose"
	"github.com/meedoomostafa/devdiag/internal/collectors/composestatus"
	"github.com/meedoomostafa/devdiag/internal/collectors/config"
	"github.com/meedoomostafa/devdiag/internal/collectors/cuda"
	"github.com/meedoomostafa/devdiag/internal/collectors/disk"
	"github.com/meedoomostafa/devdiag/internal/collectors/docker"
	"github.com/meedoomostafa/devdiag/internal/collectors/env"
	"github.com/meedoomostafa/devdiag/internal/collectors/git"
	"github.com/meedoomostafa/devdiag/internal/collectors/gpu"
	"github.com/meedoomostafa/devdiag/internal/collectors/gpudocker"
	"github.com/meedoomostafa/devdiag/internal/collectors/host"
	"github.com/meedoomostafa/devdiag/internal/collectors/hostruntime"
	"github.com/meedoomostafa/devdiag/internal/collectors/network"
	"github.com/meedoomostafa/devdiag/internal/collectors/permission"
	"github.com/meedoomostafa/devdiag/internal/collectors/podman"
	"github.com/meedoomostafa/devdiag/internal/collectors/port"
	"github.com/meedoomostafa/devdiag/internal/collectors/pythonml"
	"github.com/meedoomostafa/devdiag/internal/collectors/repo"
	"github.com/meedoomostafa/devdiag/internal/collectors/runtime"
	"github.com/meedoomostafa/devdiag/internal/collectors/security"
	"github.com/meedoomostafa/devdiag/internal/collectors/systemd"
	"github.com/meedoomostafa/devdiag/internal/findings"
	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/rulepack"
	"github.com/meedoomostafa/devdiag/internal/rules"
	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/version"
)

// ScanOptions holds behavior-affecting scan configuration.
type ScanOptions struct {
	Path         string
	Profile      string
	RulePackPath string
	RedactLevel  string
	CI           bool
}

// RepoSignals holds repository signal detection results used for conditional
// collector selection and rule evaluation.
type RepoSignals struct {
	Root          string
	HasDocker     bool
	HasPodman     bool
	HasContainers bool
	HasCI         bool
	HasPython     bool
}

// CollectorFactory builds the collector list and signals from scan options.
type CollectorFactory interface {
	Build(opts ScanOptions) ([]collectors.Collector, RepoSignals)
}

// CollectorRunner executes collectors concurrently.
type CollectorRunner interface {
	Run(ctx context.Context, collectors []collectors.Collector) []schema.CollectorResult
	RunWithObserver(ctx context.Context, collectors []collectors.Collector, observer collectors.Observer) []schema.CollectorResult
}

// RuleEngine evaluates a snapshot and returns findings.
type RuleEngine interface {
	Evaluate(snapshot graph.NormalizedSnapshot) ([]schema.Finding, error)
}

// EngineFactory creates rule engines.
type EngineFactory interface {
	NewM1() RuleEngine
	NewM6() RuleEngine
	NewM8() RuleEngine
}

// ScannerDeps holds injectable dependencies for a Scanner.
type ScannerDeps struct {
	CollectorFactory CollectorFactory
	Runner           CollectorRunner
	Engines          EngineFactory
	RunID            func() string
	Now              func() time.Time
}

// Scanner orchestrates a diagnostic scan with injectable dependencies.
type Scanner struct {
	CollectorFactory CollectorFactory
	Runner           CollectorRunner
	Engines          EngineFactory
	RunID            func() string
	Now              func() time.Time
}

// NewScanner creates a Scanner from the given dependencies.
func NewScanner(deps ScannerDeps) *Scanner {
	return &Scanner{
		CollectorFactory: deps.CollectorFactory,
		Runner:           deps.Runner,
		Engines:          deps.Engines,
		RunID:            deps.RunID,
		Now:              deps.Now,
	}
}

// Scan runs a diagnostic scan and returns the report.
func Scan(ctx context.Context, opts ScanOptions, sink EventSink) (*schema.Report, error) {
	return NewScanner(DefaultScannerDeps()).Scan(ctx, opts, sink)
}

// Scan orchestrates the full scan lifecycle and emits events to the sink.
func (s *Scanner) Scan(ctx context.Context, opts ScanOptions, sink EventSink) (*schema.Report, error) {
	startTime := s.Now()
	runID := s.RunID()

	emit := func(e Event) {
		if sink == nil {
			return
		}
		if e.Timestamp.IsZero() {
			e.Timestamp = s.Now()
		}
		if e.RunID == "" {
			e.RunID = runID
		}
		if e.Path == "" {
			e.Path = opts.Path
		}
		e.Message = sanitizeString(e.Message, opts.RedactLevel)
		e.Error = sanitizeString(e.Error, opts.RedactLevel)
		sink.Emit(e)
	}

	emit(Event{
		Type:    EventScanStarted,
		Message: "scan started",
	})

	collectorsList, signals := s.CollectorFactory.Build(opts)

	observer := &eventObserver{emit: emit}
	results := s.Runner.RunWithObserver(ctx, collectorsList, observer)

	snapshot := graph.NewSnapshotBuilder().Build(results)

	var allFindings []schema.Finding

	// Evaluate M1 policies
	m1Engine := s.Engines.NewM1()
	m1Findings, err := m1Engine.Evaluate(snapshot)
	if err != nil {
		emit(Event{
			Type:  EventScanFailed,
			Error: err.Error(),
			Err:   err,
		})
		return nil, err
	}
	emit(Event{
		Type:       EventRuleEvaluated,
		RuleEngine: "m1",
		Message:    fmt.Sprintf("M1 engine evaluated %d findings", len(m1Findings)),
	})
	for _, f := range m1Findings {
		emit(Event{
			Type:       EventFindingAdded,
			FindingID:  f.ID,
			Severity:   f.Severity,
			Confidence: f.Confidence,
			Message:    fmt.Sprintf("finding %s added", f.ID),
		})
	}
	allFindings = append(allFindings, m1Findings...)

	// Evaluate M6 policies when profile is ai-ml
	if opts.Profile == "ai-ml" {
		m6Engine := s.Engines.NewM6()
		m6Findings, err := m6Engine.Evaluate(snapshot)
		if err != nil {
			emit(Event{
				Type:  EventScanFailed,
				Error: err.Error(),
				Err:   err,
			})
			return nil, err
		}
		emit(Event{
			Type:       EventRuleEvaluated,
			RuleEngine: "m6",
			Message:    fmt.Sprintf("M6 engine evaluated %d findings", len(m6Findings)),
		})
		for _, f := range m6Findings {
			emit(Event{
				Type:       EventFindingAdded,
				FindingID:  f.ID,
				Severity:   f.Severity,
				Confidence: f.Confidence,
				Message:    fmt.Sprintf("finding %s added", f.ID),
			})
		}
		allFindings = append(allFindings, m6Findings...)
	}

	// Evaluate M8 policies when CI workflows exist
	if signals.HasCI || opts.CI {
		m8Engine := s.Engines.NewM8()
		m8Findings, err := m8Engine.Evaluate(snapshot)
		if err != nil {
			emit(Event{
				Type:  EventScanFailed,
				Error: err.Error(),
				Err:   err,
			})
			return nil, err
		}
		emit(Event{
			Type:       EventRuleEvaluated,
			RuleEngine: "m8",
			Message:    fmt.Sprintf("M8 engine evaluated %d findings", len(m8Findings)),
		})
		for _, f := range m8Findings {
			emit(Event{
				Type:       EventFindingAdded,
				FindingID:  f.ID,
				Severity:   f.Severity,
				Confidence: f.Confidence,
				Message:    fmt.Sprintf("finding %s added", f.ID),
			})
		}
		allFindings = append(allFindings, m8Findings...)
	}

	// Evaluate external rule pack
	if opts.RulePackPath != "" {
		eval := rulepack.EvaluateRegoFile(ctx, opts.RulePackPath, snapshot)
		if !eval.Valid {
			err := fmt.Errorf("rule pack validation failed: %s", strings.Join(eval.Errors, "; "))
			emit(Event{
				Type:  EventScanFailed,
				Error: err.Error(),
				Err:   err,
			})
			return nil, err
		}
		allFindings = append(allFindings, eval.Findings...)
		results = append(results, schema.CollectorResult{
			Name:   "rulepack",
			Status: schema.CollectorOK,
			Evidence: []schema.Evidence{
				{Source: "rulepack_id", Value: eval.Pack.ID},
				{Source: "rulepack_engine", Value: eval.Pack.Engine},
				{Source: "rulepack_findings", Value: fmt.Sprintf("%d", len(eval.Findings))},
			},
		})
		emit(Event{
			Type:       EventRuleEvaluated,
			RuleEngine: "rulepack",
			Message:    fmt.Sprintf("rule pack evaluated %d findings", len(eval.Findings)),
		})
		for _, f := range eval.Findings {
			emit(Event{
				Type:       EventFindingAdded,
				FindingID:  f.ID,
				Severity:   f.Severity,
				Confidence: f.Confidence,
				Message:    fmt.Sprintf("finding %s added", f.ID),
			})
		}
	}

	aggregator := findings.NewAggregator()
	sortedFindings := aggregator.Add(allFindings)

	report := &schema.Report{
		SchemaVersion:   schema.SchemaVersion,
		DevDiagVersion:  version.Version,
		RunID:           runID,
		RedactionStatus: opts.RedactLevel,
		Repo:            schema.RepoInfo{Root: signals.Root},
		Host:            populateHostInfo(results),
		Collectors:      results,
		Findings:        sortedFindings,
	}

	emit(Event{
		Type:       EventScanCompleted,
		DurationMs: s.Now().Sub(startTime).Milliseconds(),
		Message:    fmt.Sprintf("scan completed with %d findings", len(sortedFindings)),
	})

	return report, nil
}

// DefaultScannerDeps returns production dependencies.
func DefaultScannerDeps() ScannerDeps {
	return ScannerDeps{
		CollectorFactory: defaultCollectorFactory{},
		Runner:           collectors.NewRunner(),
		Engines:          defaultEngineFactory{},
		RunID:            generateRunID,
		Now:              time.Now,
	}
}

// generateRunID creates a simple run identifier.
func generateRunID() string {
	ts := time.Now().UTC()
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return fmt.Sprintf("%s_%04x", ts.Format("2006-01-02T15:04:05Z"), ts.UnixNano()%0xFFFF)
	}
	return fmt.Sprintf("%s_%s", ts.Format("2006-01-02T15:04:05Z"), hex.EncodeToString(suffix))
}

// populateHostInfo extracts host metadata from the host collector evidence.
func populateHostInfo(collectorResults []schema.CollectorResult) schema.HostInfo {
	var host schema.HostInfo
	for _, c := range collectorResults {
		if c.Name != "host" {
			continue
		}
		for _, ev := range c.Evidence {
			switch ev.Source {
			case "host_os_id":
				host.OS = ev.Value
			case "host_os_version":
				host.Version = ev.Value
			case "host_kernel":
				host.Kernel = ev.Value
			case "host_arch":
				host.Arch = ev.Value
			}
		}
	}
	return host
}

// eventObserver adapts collector runner callbacks to app events.
type eventObserver struct {
	emit func(Event)
}

func (o *eventObserver) CollectorStarted(name string) {
	o.emit(Event{
		Type:      EventCollectorStarted,
		Collector: name,
		Message:   fmt.Sprintf("collector %s started", name),
	})
}

func (o *eventObserver) CollectorDone(result schema.CollectorResult, duration time.Duration) {
	statusStr := string(result.Status)
	if statusStr == "" {
		statusStr = "unknown"
	}
	evt := Event{
		Type:       EventCollectorDone,
		Collector:  result.Name,
		Status:     result.Status,
		DurationMs: duration.Milliseconds(),
		Message:    fmt.Sprintf("collector %s done with status %s", result.Name, statusStr),
	}
	if result.Status == schema.CollectorTimeout {
		evt.Message = fmt.Sprintf("collector %s timed out", result.Name)
	}
	o.emit(evt)
}

// defaultCollectorFactory builds the collector list from scan options.
type defaultCollectorFactory struct{}

func (f defaultCollectorFactory) Build(opts ScanOptions) ([]collectors.Collector, RepoSignals) {
	absPath, err := filepath.Abs(opts.Path)
	if err != nil {
		absPath = opts.Path
	}

	repoHasDocker := repo.HasDockerSignal(absPath)
	repoHasPodman := repo.HasPodmanSignal(absPath)
	repoHasContainers := repoHasDocker || repoHasPodman

	allCollectors := []collectors.Collector{
		&config.Collector{Root: absPath},
		&repo.Collector{Root: absPath},
		&env.Collector{Root: absPath},
		&compose.Collector{Root: absPath},
		&git.Collector{Root: absPath},
		&runtime.Collector{Root: absPath},
		&host.Collector{},
		&hostruntime.Collector{},
		&disk.Collector{Path: absPath},
		&port.Collector{},
		&network.Collector{},
		&systemd.Collector{RepoExpectsDocker: repoHasDocker},
		&security.Collector{Root: absPath},
		&permission.Collector{Root: absPath},
		&collectors.SelfCollector{},
	}

	if repoHasContainers {
		allCollectors = append(allCollectors,
			&docker.Collector{},
			&podman.Collector{},
			&composestatus.Collector{Root: absPath},
		)
	}

	repoHasCI := repo.HasCISignal(absPath)
	if repoHasCI || opts.CI {
		allCollectors = append(allCollectors, &ci.Collector{Root: absPath})
	}

	if opts.Profile == "ai-ml" {
		allCollectors = append(allCollectors,
			&gpu.Collector{},
			&cuda.Collector{},
		)
		repoHasPython := repo.HasPythonSignal(absPath)
		if repoHasPython || opts.Profile == "ai-ml" {
			allCollectors = append(allCollectors, &pythonml.Collector{})
		}
		allCollectors = append(allCollectors,
			&gpudocker.Collector{},
			&cache.Collector{RepoRoot: absPath},
		)
	}

	signals := RepoSignals{
		Root:          absPath,
		HasDocker:     repoHasDocker,
		HasPodman:     repoHasPodman,
		HasContainers: repoHasContainers,
		HasCI:         repoHasCI,
		HasPython:     repo.HasPythonSignal(absPath),
	}

	return allCollectors, signals
}

// defaultEngineFactory creates real rule engines.
type defaultEngineFactory struct{}

func (f defaultEngineFactory) NewM1() RuleEngine { return rules.NewM1Engine() }
func (f defaultEngineFactory) NewM6() RuleEngine { return rules.NewM6Engine() }
func (f defaultEngineFactory) NewM8() RuleEngine { return rules.NewM8Engine() }
