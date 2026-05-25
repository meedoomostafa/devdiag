package security

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollector_ReadsSELinuxAndAppArmorState(t *testing.T) {
	dir := t.TempDir()
	selinuxPath := filepath.Join(dir, "selinux-enforce")
	apparmorPath := filepath.Join(dir, "apparmor-enabled")
	if err := os.WriteFile(selinuxPath, []byte("1\n"), 0o644); err != nil {
		t.Fatalf("write selinux fixture: %v", err)
	}
	if err := os.WriteFile(apparmorPath, []byte("Y\n"), 0o644); err != nil {
		t.Fatalf("write apparmor fixture: %v", err)
	}

	c := &Collector{
		SELinuxEnforcePath:  selinuxPath,
		AppArmorEnabledPath: apparmorPath,
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Status != schema.CollectorOK {
		t.Fatalf("status = %s, want ok", res.Status)
	}
	assertEvidence(t, res.Evidence, "selinux_status", "enforcing")
	assertEvidence(t, res.Evidence, "apparmor_enabled", "true")
}

func TestCollector_MissingSecurityPathsAreUnavailableEvidence(t *testing.T) {
	c := &Collector{
		SELinuxEnforcePath:  filepath.Join(t.TempDir(), "missing-selinux"),
		AppArmorEnabledPath: filepath.Join(t.TempDir(), "missing-apparmor"),
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	assertEvidence(t, res.Evidence, "selinux_status", "unavailable")
	assertEvidence(t, res.Evidence, "apparmor_enabled", "unavailable")
}

func TestCollector_ReadsSELinuxAndAppArmorDenials(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	logData := `type=AVC msg=audit(1710000000.1:42): avc:  denied  { read } for  pid=123 comm="node" name="data.db" dev="sda1" ino=12 scontext=system_u:system_r:container_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
audit: type=1400 audit(1710000001.2:43): apparmor="DENIED" operation="open" profile="docker-default" name="/workspace/config.json" pid=124 comm="python" requested_mask="r" denied_mask="r" fsuid=1000 ouid=1000
`
	if err := os.WriteFile(logPath, []byte(logData), 0o644); err != nil {
		t.Fatalf("write security log fixture: %v", err)
	}

	c := &Collector{
		SELinuxEnforcePath:  filepath.Join(dir, "missing-selinux"),
		AppArmorEnabledPath: filepath.Join(dir, "missing-apparmor"),
		SecurityLogPaths:    []string{logPath},
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	assertEvidenceContains(t, res.Evidence, "selinux_denial", "comm=node")
	assertEvidenceContains(t, res.Evidence, "selinux_denial", "name=data.db")
	assertEvidenceContains(t, res.Evidence, "apparmor_denial", "profile=docker-default")
	assertEvidenceContains(t, res.Evidence, "apparmor_denial", "name=/workspace/config.json")
}

func TestCollector_FiltersDenialsByRootWhenProvided(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	logData := `audit: type=1400 audit(1710000001.2:43): apparmor="DENIED" operation="open" profile="docker-default" name="/other-project/config.json" pid=124 comm="python"
audit: type=1400 audit(1710000002.2:44): apparmor="DENIED" operation="open" profile="docker-default" name="/workspace/current/config.json" pid=125 comm="python"
`
	if err := os.WriteFile(logPath, []byte(logData), 0o644); err != nil {
		t.Fatalf("write security log fixture: %v", err)
	}

	c := &Collector{
		SELinuxEnforcePath:  filepath.Join(dir, "missing-selinux"),
		AppArmorEnabledPath: filepath.Join(dir, "missing-apparmor"),
		SecurityLogPaths:    []string{logPath},
		Root:                "/workspace/current",
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	assertEvidenceContains(t, res.Evidence, "apparmor_denial", "name=/workspace/current/config.json")
	for _, ev := range res.Evidence {
		if ev.Source == "apparmor_denial" && strings.Contains(ev.Value, "/other-project") {
			t.Fatalf("unrelated denial leaked into evidence: %v", ev)
		}
	}
}

func TestCollector_AttributesSELinuxDenialUsingAuditRecordContext(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	logData := `type=AVC msg=audit(1710000000.1:42): avc:  denied  { write } for  pid=123 comm="node" name="cache" scontext=system_u:system_r:container_t:s0:c123,c456 tcontext=unconfined_u:object_r:default_t:s0 tclass=dir permissive=0
type=CWD msg=audit(1710000000.1:42): cwd="/workspace/current"
type=AVC msg=audit(1710000001.1:43): avc:  denied  { read } for  pid=124 comm="node" name="secret" scontext=system_u:system_r:container_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
type=CWD msg=audit(1710000001.1:43): cwd="/other-project"
`
	if err := os.WriteFile(logPath, []byte(logData), 0o644); err != nil {
		t.Fatalf("write security log fixture: %v", err)
	}

	c := &Collector{
		SELinuxEnforcePath:  filepath.Join(dir, "missing-selinux"),
		AppArmorEnabledPath: filepath.Join(dir, "missing-apparmor"),
		SecurityLogPaths:    []string{logPath},
		Root:                "/workspace/current",
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	assertEvidenceContains(t, res.Evidence, "selinux_denial", "name=cache")
	assertEvidenceContains(t, res.Evidence, "selinux_denial", "cwd=/workspace/current")
	assertEvidenceContains(t, res.Evidence, "selinux_denial", "container_label_hint=mount_relabel_z_or_Z")
	for _, ev := range res.Evidence {
		if ev.Source == "selinux_denial" && strings.Contains(ev.Value, "name=secret") {
			t.Fatalf("unrelated SELinux denial leaked into evidence: %v", ev)
		}
	}
}

func assertEvidence(t *testing.T, evidence []schema.Evidence, source, value string) {
	t.Helper()
	for _, ev := range evidence {
		if ev.Source == source && ev.Value == value {
			return
		}
	}
	t.Fatalf("missing evidence %s=%s in %v", source, value, evidence)
}

func assertEvidenceContains(t *testing.T, evidence []schema.Evidence, source, value string) {
	t.Helper()
	for _, ev := range evidence {
		if ev.Source == source && strings.Contains(ev.Value, value) {
			return
		}
	}
	t.Fatalf("missing evidence %s containing %q in %v", source, value, evidence)
}
