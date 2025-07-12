// Package consul provides types and utilities for Consul deployment
package consul

// Config holds the complete Consul configuration
type Config struct {
	DatacenterName          string
	EnableDebugLogging      bool
	DisableVaultIntegration bool
}
