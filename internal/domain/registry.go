package domain

import (
	"sort"
	"strings"
)

// Domain represents rule and classification metadata for a diagnostic area.
type Domain struct {
	Name          string
	Label         string
	Target        string
	Prefixes      []string
	ScopePrefixes []string
	DefaultLayers []string
	TUIKey        string
	TUIVisible    bool
}

// DomainRegistry is the global database of diagnostic domains.
var DomainRegistry = []Domain{
	{
		Name:          "env",
		Label:         "Environment Variables",
		Target:        "environment",
		Prefixes:      []string{"F-ENV-"},
		ScopePrefixes: []string{"F-ENV-"},
		DefaultLayers: []string{"env"},
		TUIKey:        "1",
		TUIVisible:    true,
	},
	{
		Name:          "ci",
		Label:         "CI/Local Parity",
		Target:        "CI pipeline",
		Prefixes:      []string{"F-CI-"},
		ScopePrefixes: []string{"F-CI-"},
		DefaultLayers: []string{"ci", "local"},
		TUIKey:        "2",
		TUIVisible:    true,
	},
	{
		Name:          "containers",
		Label:         "Container Environment",
		Target:        "container environment",
		Prefixes:      []string{"F-CONTAINER-", "F-DOCKER-", "F-PODMAN-", "F-COMPOSE-"},
		ScopePrefixes: []string{"F-CONTAINER-", "F-DOCKER-", "F-PODMAN-", "F-COMPOSE-"},
		DefaultLayers: []string{"containers"},
		TUIKey:        "3",
		TUIVisible:    true,
	},
	{
		Name:          "runtime",
		Label:         "Local Runtime",
		Target:        "local runtime",
		Prefixes:      []string{"F-RUNTIME-", "F-DECL-"},
		ScopePrefixes: []string{"F-RUNTIME-"},
		DefaultLayers: []string{"runtime"},
		TUIKey:        "4",
		TUIVisible:    true,
	},
	{
		Name:          "gpu",
		Label:         "GPU/CUDA Diagnostics",
		Target:        "GPU/ML stack",
		Prefixes:      []string{"F-GPU-", "F-CUDA-", "F-ML-", "F-DOCKER-GPU-", "F-AI-"},
		ScopePrefixes: []string{"F-GPU-", "F-CUDA-", "F-ML-", "F-DOCKER-GPU-"},
		DefaultLayers: []string{"host", "runtime"},
		TUIKey:        "5",
		TUIVisible:    true,
	},
	{
		Name:          "trace",
		Label:         "Process Trace",
		Target:        "process trace",
		Prefixes:      []string{"F-TRACE-", "F-REPRO-"},
		ScopePrefixes: []string{"F-TRACE-"},
		DefaultLayers: []string{"process"},
		TUIKey:        "6",
		TUIVisible:    true,
	},
	{
		Name:          "network",
		Label:         "Network Services",
		Target:        "network services",
		Prefixes:      []string{"F-PORT-", "F-NET-", "F-NETWORK-"},
		ScopePrefixes: []string{"F-NET-"},
		DefaultLayers: []string{"network"},
		TUIKey:        "",
		TUIVisible:    false,
	},
	{
		Name:          "security",
		Label:         "Security Posture",
		Target:        "security posture",
		Prefixes:      []string{"F-SEC-", "F-SECURITY-"},
		ScopePrefixes: []string{"F-SEC-"},
		DefaultLayers: []string{"security"},
		TUIKey:        "",
		TUIVisible:    false,
	},
	{
		Name:          "cache",
		Label:         "Build Cache",
		Target:        "build cache",
		Prefixes:      []string{"F-CACHE-"},
		ScopePrefixes: []string{"F-CACHE-"},
		DefaultLayers: []string{"cache"},
		TUIKey:        "",
		TUIVisible:    false,
	},
	{
		Name:          "filesystem",
		Label:         "File System & Permissions",
		Target:        "filesystem and permissions",
		Prefixes:      []string{"F-DISK-", "F-FS-", "F-PERM-", "F-PERMISSION-"},
		ScopePrefixes: []string{"F-DISK-", "F-FS-", "F-PERM-"},
		DefaultLayers: []string{"filesystem"},
		TUIKey:        "",
		TUIVisible:    false,
	},
	{
		Name:          "git",
		Label:         "Git Repository",
		Target:        "repository",
		Prefixes:      []string{"F-GIT-", "F-PM-"},
		ScopePrefixes: []string{"F-GIT-", "F-PM-"},
		DefaultLayers: []string{"git"},
		TUIKey:        "",
		TUIVisible:    false,
	},
	{
		Name:          "config",
		Label:         "Configuration",
		Target:        "configuration",
		Prefixes:      []string{"F-CONFIG-"},
		ScopePrefixes: []string{"F-CONFIG-"},
		DefaultLayers: []string{"config"},
		TUIKey:        "",
		TUIVisible:    false,
	},
	{
		Name:          "host",
		Label:         "Host System",
		Target:        "host system",
		Prefixes:      []string{"F-HOST-"},
		ScopePrefixes: []string{"F-HOST-"},
		DefaultLayers: []string{"host"},
		TUIKey:        "",
		TUIVisible:    false,
	},
	{
		Name:          "services",
		Label:         "System Services",
		Target:        "system services",
		Prefixes:      []string{"F-SVC-"},
		ScopePrefixes: []string{"F-SVC-"},
		DefaultLayers: []string{"services"},
		TUIKey:        "",
		TUIVisible:    false,
	},
}

type prefixMapping struct {
	prefix string
	domain Domain
}

var sortedPrefixMappings []prefixMapping

func init() {
	var mappings []prefixMapping
	for _, d := range DomainRegistry {
		for _, p := range d.Prefixes {
			mappings = append(mappings, prefixMapping{
				prefix: strings.ToUpper(p),
				domain: d,
			})
		}
	}
	// Sort by prefix length descending to implement longest-prefix matching
	sort.Slice(mappings, func(i, j int) bool {
		return len(mappings[i].prefix) > len(mappings[j].prefix)
	})
	sortedPrefixMappings = mappings
}

func cloneDomain(d Domain) Domain {
	d.Prefixes = append([]string(nil), d.Prefixes...)
	d.ScopePrefixes = append([]string(nil), d.ScopePrefixes...)
	d.DefaultLayers = append([]string(nil), d.DefaultLayers...)
	return d
}

// FindDomainByFindingID matches a finding ID prefix to its registered domain using longest-prefix matching.
func FindDomainByFindingID(id string) (Domain, bool) {
	upperID := strings.ToUpper(id)
	for _, m := range sortedPrefixMappings {
		if strings.HasPrefix(upperID, m.prefix) {
			return cloneDomain(m.domain), true
		}
	}
	return Domain{}, false
}

// FindDomainByName finds a Domain by its name (case-insensitive).
func FindDomainByName(name string) (Domain, bool) {
	for _, d := range DomainRegistry {
		if strings.EqualFold(d.Name, name) {
			return cloneDomain(d), true
		}
	}
	return Domain{}, false
}

// FindDomainByTUIKey finds a Domain by its mapped TUI shortcut key.
func FindDomainByTUIKey(key string) (Domain, bool) {
	for _, d := range DomainRegistry {
		if d.TUIKey == key {
			return cloneDomain(d), true
		}
	}
	return Domain{}, false
}

// GetTUIMappedDomains returns TUI-visible domains mapped to shortcut keys, preserving stable order.
func GetTUIMappedDomains() []Domain {
	var list []Domain
	for _, d := range DomainRegistry {
		if d.TUIVisible && d.TUIKey != "" {
			list = append(list, cloneDomain(d))
		}
	}
	return list
}

// DomainPrefixes returns a defensive copy of the classification prefixes for a given domain.
func DomainPrefixes(name string) []string {
	if d, ok := FindDomainByName(name); ok {
		out := make([]string, len(d.Prefixes))
		copy(out, d.Prefixes)
		return out
	}
	return nil
}

// DomainScopePrefixes returns a defensive copy of the scoped engine prefixes for a given domain.
func DomainScopePrefixes(name string) []string {
	if d, ok := FindDomainByName(name); ok {
		out := make([]string, len(d.ScopePrefixes))
		copy(out, d.ScopePrefixes)
		return out
	}
	return nil
}
