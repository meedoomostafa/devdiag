package pathfilter

import (
	"path/filepath"
	"regexp"
	"strings"
)

// PathClass describes how DevDiag should treat a path when collecting
// project-level evidence.
type PathClass string

const (
	PathProject    PathClass = "project"
	PathDependency PathClass = "dependency"
	PathGenerated  PathClass = "generated"
	PathCache      PathClass = "cache"
	PathVCS        PathClass = "vcs"
	PathTooling    PathClass = "tooling"
	PathUnknown    PathClass = "unknown"
)

var segmentClasses = map[string]PathClass{
	".git":          PathVCS,
	".devdiag":      PathTooling,
	"node_modules":  PathDependency,
	"vendor":        PathDependency,
	".venv":         PathDependency,
	"venv":          PathDependency,
	"env":           PathDependency,
	"ENV":           PathDependency,
	"site-packages": PathDependency,
	"__pycache__":   PathCache,
	".pytest_cache": PathCache,
	".mypy_cache":   PathCache,
	".ruff_cache":   PathCache,
	".tox":          PathCache,
	".nox":          PathCache,
	".cache":        PathCache,
	"coverage":      PathGenerated,
	"dist":          PathGenerated,
	"build":         PathGenerated,
	"target":        PathGenerated,
	"bin":           PathGenerated,
	"obj":           PathGenerated,
	".next":         PathGenerated,
	".nuxt":         PathGenerated,
	".svelte-kit":   PathGenerated,
	".angular":      PathGenerated,
	".parcel-cache": PathCache,
	".turbo":        PathCache,
	".gradle":       PathCache,
	"DerivedData":   PathGenerated,
	"Pods":          PathDependency,
}

// ShouldSkipDir reports whether a directory should be skipped by default
// during project evidence discovery.
func ShouldSkipDir(name string) bool {
	_, ok := segmentClasses[name]
	return ok
}

// ClassifyPath returns the strongest path class implied by any path segment.
func ClassifyPath(root, path string) PathClass {
	rel := relativePath(root, path)
	if rel == "" || rel == "." {
		return PathProject
	}
	class := PathProject
	for _, segment := range strings.Split(filepath.ToSlash(rel), "/") {
		if segment == "" || segment == "." {
			continue
		}
		segmentClass, ok := segmentClasses[segment]
		if !ok {
			continue
		}
		if classPriority(segmentClass) > classPriority(class) {
			class = segmentClass
		}
	}
	return class
}

func classPriority(class PathClass) int {
	switch class {
	case PathDependency:
		return 5
	case PathGenerated:
		return 4
	case PathCache:
		return 3
	case PathVCS:
		return 2
	case PathTooling:
		return 1
	default:
		return 0
	}
}

// ShouldSkipPath reports whether a path should be excluded from project-level
// evidence by default.
func ShouldSkipPath(root, path string) bool {
	switch ClassifyPath(root, path) {
	case PathDependency, PathGenerated, PathCache, PathVCS, PathTooling:
		return true
	default:
		return false
	}
}

// ShouldSkipPathWithPatterns applies the built-in policy plus project-specific
// slash-style glob patterns such as ".venv/**" or "**/site-packages/**".
func ShouldSkipPathWithPatterns(root, path string, patterns []string) bool {
	if ShouldSkipPath(root, path) {
		return true
	}
	rel := filepath.ToSlash(relativePath(root, path))
	for _, pattern := range patterns {
		if matchGlob(pattern, rel) {
			return true
		}
	}
	return false
}

func IsProjectManifestPathWithPatterns(root, path string, patterns []string) bool {
	return !ShouldSkipPathWithPatterns(root, path, patterns)
}

func matchGlob(pattern, rel string) bool {
	pattern = strings.TrimSpace(filepath.ToSlash(pattern))
	if pattern == "" {
		return false
	}
	pattern = strings.TrimPrefix(pattern, "./")
	re := globRegexp(pattern)
	return re.MatchString(rel)
}

func globRegexp(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		if ch == '*' {
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				b.WriteString(".*")
				i++
				continue
			}
			b.WriteString(`[^/]*`)
			continue
		}
		if ch == '?' {
			b.WriteString(`[^/]`)
			continue
		}
		b.WriteString(regexp.QuoteMeta(string(ch)))
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

func relativePath(root, path string) string {
	if root == "" {
		root = "."
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(filepath.ToSlash(rel), "../") {
		return filepath.Clean(path)
	}
	return rel
}
