package domain

import (
	"reflect"
	"testing"
)

func TestFindDomainByFindingIDKnownPrefixes(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"F-CI-RUNTIME-001", "ci"},
		{"F-ENV-SECRET-001", "env"},
		{"F-PORT-EXPOSE-001", "network"},
		{"F-SECURITY-PERM-001", "security"},
		{"F-CONTAINER-IMAGE-001", "containers"},
		{"F-DOCKER-FILE-001", "containers"},
		{"F-PODMAN-SOCK-001", "containers"},
		{"F-GPU-CUDA-001", "gpu"},
		{"F-CACHE-STALE-001", "cache"},
		{"F-HOST-OS-001", "host"},
		{"F-PERMISSION-ROOT-001", "filesystem"},
		{"F-FS-RO-001", "filesystem"},
		{"F-DISK-SPACE-001", "filesystem"},
		{"F-PERM-EXEC-001", "filesystem"},
		{"F-GIT-LEAK-001", "git"},
		{"F-CONFIG-ERROR-001", "config"},
		{"F-RUNTIME-DECL-001", "runtime"},
		{"F-SVC-SYSTEMD-001", "services"},
	}
	for _, tt := range tests {
		got, ok := FindDomainByFindingID(tt.id)
		if !ok {
			t.Errorf("FindDomainByFindingID(%q) not found", tt.id)
			continue
		}
		if got.Name != tt.want {
			t.Errorf("FindDomainByFindingID(%q) = %q, want %q", tt.id, got.Name, tt.want)
		}
	}
}

func TestFindDomainByFindingIDUsesLongestPrefix(t *testing.T) {
	// F-DOCKER-GPU-001 starts with F-DOCKER- (containers) but matches F-DOCKER-GPU- (gpu) due to longest prefix.
	got, ok := FindDomainByFindingID("F-DOCKER-GPU-001")
	if !ok {
		t.Fatal("F-DOCKER-GPU-001 not found")
	}
	if got.Name != "gpu" {
		t.Errorf("F-DOCKER-GPU-001 resolved to %q, want %q", got.Name, "gpu")
	}
}

func TestFindDomainByName(t *testing.T) {
	got, ok := FindDomainByName("containers")
	if !ok {
		t.Fatal("containers domain not found by name")
	}
	if got.Label != "Container Environment" {
		t.Errorf("unexpected label: %q", got.Label)
	}

	_, ok = FindDomainByName("nonexistent")
	if ok {
		t.Error("nonexistent domain found")
	}
}

func TestFindDomainByTUIKey(t *testing.T) {
	got, ok := FindDomainByTUIKey("3")
	if !ok {
		t.Fatal("TUI key 3 not found")
	}
	if got.Name != "containers" {
		t.Errorf("TUI key 3 resolved to %q, want containers", got.Name)
	}

	_, ok = FindDomainByTUIKey("9")
	if ok {
		t.Error("TUI key 9 should not be found")
	}
}

func TestGetTUIMappedDomainsStableOrder(t *testing.T) {
	list := GetTUIMappedDomains()
	if len(list) != 6 {
		t.Fatalf("expected 6 mapped TUI domains, got %d", len(list))
	}
	expectedOrder := []string{"env", "ci", "containers", "runtime", "gpu", "trace"}
	for i, name := range expectedOrder {
		if list[i].Name != name {
			t.Errorf("idx %d: got %q, want %q", i, list[i].Name, name)
		}
	}
}

func TestDomainPrefixesReturnsCopy(t *testing.T) {
	name := "gpu"
	prefixes1 := DomainPrefixes(name)
	if len(prefixes1) == 0 {
		t.Fatal("prefixes empty")
	}
	orig := prefixes1[0]
	prefixes1[0] = "MUTATED"

	prefixes2 := DomainPrefixes(name)
	if prefixes2[0] == "MUTATED" {
		t.Errorf("DomainPrefixes returned same underlying slice; mutation leaked")
	}
	if prefixes2[0] != orig {
		t.Errorf("unexpected prefix mismatch: %q vs %q", prefixes2[0], orig)
	}
}

func TestDomainScopePrefixesReturnsCopy(t *testing.T) {
	name := "gpu"
	prefixes1 := DomainScopePrefixes(name)
	if len(prefixes1) == 0 {
		t.Fatal("scope prefixes empty")
	}
	orig := prefixes1[0]
	prefixes1[0] = "MUTATED"

	prefixes2 := DomainScopePrefixes(name)
	if prefixes2[0] == "MUTATED" {
		t.Errorf("DomainScopePrefixes returned same underlying slice; mutation leaked")
	}
	if prefixes2[0] != orig {
		t.Errorf("unexpected scope prefix mismatch: %q vs %q", prefixes2[0], orig)
	}
}

func TestDefaultLayersUsesRegistry(t *testing.T) {
	got, ok := FindDomainByFindingID("F-CI-RUNTIME-001")
	if !ok {
		t.Fatal("F-CI-RUNTIME-001 not found")
	}
	wantLayers := []string{"ci", "local"}
	if !reflect.DeepEqual(got.DefaultLayers, wantLayers) {
		t.Errorf("default layers = %v, want %v", got.DefaultLayers, wantLayers)
	}
}

func TestFPermInFilesystemScopePrefixes(t *testing.T) {
	scopePrefixes := DomainScopePrefixes("filesystem")
	found := false
	for _, p := range scopePrefixes {
		if p == "F-PERM-" {
			found = true
			break
		}
	}
	if !found {
		t.Error("F-PERM- not found in filesystem ScopePrefixes")
	}
}
