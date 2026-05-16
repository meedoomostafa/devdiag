package trace

import "testing"

func TestParseScopesValid(t *testing.T) {
	cases := []struct {
		input string
		want  []Scope
	}{
		{"file", []Scope{ScopeFile}},
		{"process", []Scope{ScopeProcess}},
		{"network", []Scope{ScopeNetwork}},
		{"file,process", []Scope{ScopeFile, ScopeProcess}},
		{"file, process, network", []Scope{ScopeFile, ScopeProcess, ScopeNetwork}},
	}
	for _, c := range cases {
		got, err := ParseScopes(c.input)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", c.input, err)
		}
		if len(got) != len(c.want) {
			t.Fatalf("ParseScopes(%q) = %v, want %v", c.input, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("ParseScopes(%q)[%d] = %v, want %v", c.input, i, got[i], c.want[i])
			}
		}
	}
}

func TestParseScopesInvalid(t *testing.T) {
	cases := []string{"", "gpu", "file,gpu"}
	for _, input := range cases {
		_, err := ParseScopes(input)
		if err == nil {
			t.Fatalf("expected error for %q, got nil", input)
		}
	}
}

func TestParseScopesCaseInsensitive(t *testing.T) {
	scopes, err := ParseScopes("FILE")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scopes) != 1 || scopes[0] != ScopeFile {
		t.Fatalf("expected [file], got %v", scopes)
	}
}
