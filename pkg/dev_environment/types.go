package dev_environment

import (
	"time"
)

// Config holds configuration for the development environment setup
type Config struct {
	User            string   // User to install code-server for
	Password        string   // Password for code-server authentication
	SkipGH          bool     // Skip GitHub CLI installation
	SkipClaude      bool     // Skip Claude Code extension
	AllowedNetworks []string // Additional networks to allow for port 8080
}

// Constants
const (
	CodeServerPort    = 8080
	CodeServerVersion = "4.92.2" // Latest stable version
	CodeServerURL     = "https://github.com/coder/code-server/releases/download/v%s/code-server_%s_amd64.deb"

	// Network ranges
	TailscaleNetwork = "100.64.0.0/10"
	ConsulNetwork    = "10.0.0.0/8" // Adjust based on your Consul setup
	LocalNetwork     = "192.168.0.0/16"

	// Timeouts
	InstallTimeout = 5 * time.Minute
	AuthTimeout    = 2 * time.Minute
)
