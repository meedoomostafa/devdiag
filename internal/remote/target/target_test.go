package target

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    *Target
		wantErr bool
	}{
		{
			name: "ssh user@host",
			raw:  "user@host",
			want: &Target{Kind: KindSSH, Raw: "user@host", User: "user", Host: "host", Port: 22},
		},
		{
			name: "ssh host only",
			raw:  "host.example.com",
			want: &Target{Kind: KindSSH, Raw: "host.example.com", User: "", Host: "host.example.com", Port: 22},
		},
		{
			name: "ssh user@host:port",
			raw:  "user@host:2222",
			want: &Target{Kind: KindSSH, Raw: "user@host:2222", User: "user", Host: "host", Port: 2222},
		},
		{
			name: "ssh url",
			raw:  "ssh://user@host:2222",
			want: &Target{Kind: KindSSH, Raw: "ssh://user@host:2222", User: "user", Host: "host", Port: 2222},
		},
		{
			name:    "ssh invalid port",
			raw:     "user@host:abc",
			wantErr: true,
		},
		{
			name:    "ssh empty user",
			raw:     "@host",
			wantErr: true,
		},
		{
			name:    "ssh shell metacharacters",
			raw:     "user@host;rm -rf",
			wantErr: true,
		},
		{
			name: "container simple",
			raw:  "container:mycontainer",
			want: &Target{Kind: KindContainer, Raw: "container:mycontainer", Container: "mycontainer", Runtime: "auto"},
		},
		{
			name: "container docker",
			raw:  "container:docker/api",
			want: &Target{Kind: KindContainer, Raw: "container:docker/api", Container: "api", Runtime: "docker"},
		},
		{
			name: "container podman",
			raw:  "container:podman/api",
			want: &Target{Kind: KindContainer, Raw: "container:podman/api", Container: "api", Runtime: "podman"},
		},
		{
			name:    "container empty",
			raw:     "container:",
			wantErr: true,
		},
		{
			name:    "container bad runtime",
			raw:     "container:lxc/api",
			wantErr: true,
		},
		{
			name:    "container shell metacharacters",
			raw:     "container:api;rm -rf",
			wantErr: true,
		},
		{
			name: "k8s simple",
			raw:  "k8s:default/api-pod",
			want: &Target{Kind: KindK8s, Raw: "k8s:default/api-pod", Namespace: "default", Pod: "api-pod"},
		},
		{
			name: "k8s with context",
			raw:  "k8s:prod/default/api-pod",
			want: &Target{Kind: KindK8s, Raw: "k8s:prod/default/api-pod", Context: "prod", Namespace: "default", Pod: "api-pod"},
		},
		{
			name:    "k8s empty",
			raw:     "k8s:",
			wantErr: true,
		},
		{
			name:    "k8s bad parts",
			raw:     "k8s:a/b/c/d",
			wantErr: true,
		},
		{
			name:    "empty target",
			raw:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.Kind != tt.want.Kind {
				t.Errorf("Kind = %q, want %q", got.Kind, tt.want.Kind)
			}
			if got.User != tt.want.User {
				t.Errorf("User = %q, want %q", got.User, tt.want.User)
			}
			if got.Host != tt.want.Host {
				t.Errorf("Host = %q, want %q", got.Host, tt.want.Host)
			}
			if got.Port != tt.want.Port {
				t.Errorf("Port = %d, want %d", got.Port, tt.want.Port)
			}
			if got.Container != tt.want.Container {
				t.Errorf("Container = %q, want %q", got.Container, tt.want.Container)
			}
			if got.Runtime != tt.want.Runtime {
				t.Errorf("Runtime = %q, want %q", got.Runtime, tt.want.Runtime)
			}
			if got.Namespace != tt.want.Namespace {
				t.Errorf("Namespace = %q, want %q", got.Namespace, tt.want.Namespace)
			}
			if got.Pod != tt.want.Pod {
				t.Errorf("Pod = %q, want %q", got.Pod, tt.want.Pod)
			}
			if got.Context != tt.want.Context {
				t.Errorf("Context = %q, want %q", got.Context, tt.want.Context)
			}
		})
	}
}

func TestTargetString(t *testing.T) {
	tests := []struct {
		name string
		t    Target
		want string
	}{
		{name: "ssh full", t: Target{Kind: KindSSH, User: "u", Host: "h", Port: 22}, want: "u@h"},
		{name: "ssh port", t: Target{Kind: KindSSH, User: "u", Host: "h", Port: 2222}, want: "u@h:2222"},
		{name: "ssh no user", t: Target{Kind: KindSSH, Host: "h", Port: 22}, want: "h"},
		{name: "container auto", t: Target{Kind: KindContainer, Container: "api"}, want: "container:api"},
		{name: "container docker", t: Target{Kind: KindContainer, Container: "api", Runtime: "docker"}, want: "container:docker/api"},
		{name: "k8s simple", t: Target{Kind: KindK8s, Namespace: "default", Pod: "p"}, want: "k8s:default/p"},
		{name: "k8s context", t: Target{Kind: KindK8s, Context: "c", Namespace: "ns", Pod: "p"}, want: "k8s:c/ns/p"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.t.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
