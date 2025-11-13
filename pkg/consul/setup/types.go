package setup

// DEPRECATED: All constants moved to pkg/consul/constants.go
// This file maintained temporarily for backwards compatibility.
// TODO: Remove after all references are updated.

import "github.com/CodeMonkeyCybersecurity/eos/pkg/consul"

// Re-export constants from pkg/consul for backwards compatibility
const (
	ConsulUser     = consul.ConsulUser
	ConsulHome     = consul.ConsulConfigDir
	ConsulOptDir   = consul.ConsulOptDir
	ConsulLogDir   = consul.ConsulLogDir
	ConsulShell    = "/bin/false" // Not security-critical, kept local
	ConfigDirPerms = consul.ConsulConfigDirPerm
	OptDirPerms    = consul.ConsulOptDirPerm
	LogDirPerms    = consul.ConsulLogDirPerm
)
