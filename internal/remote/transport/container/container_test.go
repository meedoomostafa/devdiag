package container

import (
	"testing"

	"github.com/meedoomostafa/devdiag/internal/remote/transport"
)

func TestParseFactOutput(t *testing.T) {
	stdout := `/bin/sh
Linux
x86_64
0
0
/
/
/bin/sh






/bin/tar
tmp_writable
`
	res := &transport.RemoteProbeResult{Tools: make(map[string]bool)}
	parseFactOutput(res, stdout)

	if res.Shell != "/bin/sh" {
		t.Errorf("Shell = %q, want /bin/sh", res.Shell)
	}
	if res.OS != "Linux" {
		t.Errorf("OS = %q, want Linux", res.OS)
	}
	if !res.HomeWritable {
		t.Error("expected tmp writable")
	}
	if !res.Tools["sh"] {
		t.Error("expected sh available")
	}
	if res.Tools["bash"] {
		t.Error("expected bash not available")
	}
	if !res.HasTar {
		t.Error("expected tar available")
	}
}

func TestParseFactOutput_ReadOnly(t *testing.T) {
	stdout := `/bin/sh
Linux
x86_64
0
0
/
/









tmp_not_writable
`
	res := &transport.RemoteProbeResult{Tools: make(map[string]bool)}
	parseFactOutput(res, stdout)

	if res.HomeWritable {
		t.Error("expected tmp not writable")
	}
}
