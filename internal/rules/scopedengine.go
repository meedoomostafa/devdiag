package rules

import (
	"strings"

	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// ScopedEngine implements PolicyEngine by evaluating underlying engines and filtering
// the resulting findings by the specified finding ID prefixes.
type ScopedEngine struct {
	engines  []PolicyEngine
	prefixes []string
}

// NewScopedEngine wraps a single engine with prefix-based filtering.
func NewScopedEngine(engine PolicyEngine, prefixes ...string) PolicyEngine {
	return &ScopedEngine{
		engines:  []PolicyEngine{engine},
		prefixes: prefixes,
	}
}

// NewCompositeScopedEngine wraps multiple engines with prefix-based filtering.
func NewCompositeScopedEngine(engines []PolicyEngine, prefixes ...string) PolicyEngine {
	return &ScopedEngine{
		engines:  engines,
		prefixes: prefixes,
	}
}

// Evaluate implements the PolicyEngine interface.
func (e *ScopedEngine) Evaluate(snapshot graph.NormalizedSnapshot) ([]schema.Finding, error) {
	var all []schema.Finding
	for _, eng := range e.engines {
		findings, err := eng.Evaluate(snapshot)
		if err != nil {
			return nil, err
		}
		all = append(all, findings...)
	}

	var filtered []schema.Finding
	for _, f := range all {
		id := strings.ToUpper(f.ID)
		matched := false
		for _, p := range e.prefixes {
			if strings.HasPrefix(id, strings.ToUpper(p)) {
				matched = true
				break
			}
		}
		if matched {
			filtered = append(filtered, f)
		}
	}
	return filtered, nil
}

// NewEnvEngine evaluates M1Engine and filters to F-ENV- domain findings.
func NewEnvEngine() PolicyEngine {
	return NewScopedEngine(NewM1Engine(), "F-ENV-")
}

// NewPortEngine evaluates M1Engine and filters to F-PORT- domain findings.
func NewPortEngine() PolicyEngine {
	return NewScopedEngine(NewM1Engine(), "F-PORT-")
}

// NewRuntimeEngine evaluates M1Engine and filters to F-RUNTIME- domain findings.
func NewRuntimeEngine() PolicyEngine {
	return NewScopedEngine(NewM1Engine(), "F-RUNTIME-")
}

// NewGitEngine evaluates M1Engine and filters to F-GIT- and F-PM- domain findings.
func NewGitEngine() PolicyEngine {
	return NewScopedEngine(NewM1Engine(), "F-GIT-", "F-PM-")
}

// NewServiceEngine evaluates M1Engine and filters to F-SVC- domain findings.
func NewServiceEngine() PolicyEngine {
	return NewScopedEngine(NewM1Engine(), "F-SVC-")
}

// NewNetworkEngine evaluates M1Engine and filters to F-NET- domain findings.
func NewNetworkEngine() PolicyEngine {
	return NewScopedEngine(NewM1Engine(), "F-NET-")
}

// NewFilesystemEngine evaluates M1Engine and filters to F-DISK-, F-FS-, and F-PERM- domain findings.
func NewFilesystemEngine() PolicyEngine {
	return NewScopedEngine(NewM1Engine(), "F-DISK-", "F-FS-", "F-PERM-")
}

// NewSecurityEngine evaluates M1Engine and filters to F-SEC- domain findings.
func NewSecurityEngine() PolicyEngine {
	return NewScopedEngine(NewM1Engine(), "F-SEC-")
}

// NewContainerEngine evaluates M1/M6 engines and filters to container / GPU findings.
func NewContainerEngine(includeGPU bool) PolicyEngine {
	if !includeGPU {
		return NewScopedEngine(NewM1Engine(), "F-CONTAINER-", "F-DOCKER-", "F-PODMAN-", "F-COMPOSE-")
	}
	return NewCompositeScopedEngine(
		[]PolicyEngine{NewM1Engine(), NewM6Engine()},
		"F-CONTAINER-", "F-DOCKER-", "F-PODMAN-", "F-COMPOSE-", "F-GPU-",
	)
}
