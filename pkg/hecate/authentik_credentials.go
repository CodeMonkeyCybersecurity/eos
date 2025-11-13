package hecate

import "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"

// DiscoverAuthentikCredentials exposes the shared Authentik credential discovery
// logic for other packages (CLI commands, helpers) without duplicating the
// private implementation. The heavy lifting remains in discoverAuthentikCredentials.
func DiscoverAuthentikCredentials(rc *eos_io.RuntimeContext) (string, string, error) {
	return discoverAuthentikCredentials(rc)
}
