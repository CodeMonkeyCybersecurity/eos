package ssh

import (
	"os/user"
	"testing"
)

func TestBuildConnectionConfig(t *testing.T) {
	currentUser, _ := user.Current()

	tests := []struct {
		name        string
		host        string
		user        string
		port        string
		wantHost    string
		wantUser    string
		wantPort    string
		expectError bool
	}{
		{
			name:     "user host and port embedded",
			host:     "alice@example.com:2222",
			wantHost: "example.com",
			wantUser: "alice",
			wantPort: "2222",
		},
		{
			name:     "override user and port flags win",
			host:     "example.com",
			user:     "henry",
			port:     "2200",
			wantHost: "example.com",
			wantUser: "henry",
			wantPort: "2200",
		},
		{
			name:     "host with port uses default user",
			host:     "vhost1:2022",
			wantHost: "vhost1",
			wantUser: currentUser.Username,
			wantPort: "2022",
		},
		{
			name:        "missing host errors",
			host:        "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := BuildConnectionConfig(tt.host, tt.user, tt.port, "", "", "")
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error but got config %+v", cfg)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cfg.Host != tt.wantHost {
				t.Fatalf("host mismatch: got %s want %s", cfg.Host, tt.wantHost)
			}
			if cfg.User != tt.wantUser {
				t.Fatalf("user mismatch: got %s want %s", cfg.User, tt.wantUser)
			}
			if cfg.Port != tt.wantPort {
				t.Fatalf("port mismatch: got %s want %s", cfg.Port, tt.wantPort)
			}
		})
	}
}
