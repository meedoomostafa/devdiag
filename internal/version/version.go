package version

// Version is injected at build time via ldflags
// (-X github.com/meedoomostafa/devdiag/internal/version.Version=<tag>).
// The "dev" default makes uninjected builds identifiable instead of
// silently reporting a stale release number.
var Version = "dev"
