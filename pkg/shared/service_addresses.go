// Package shared provides centralized service address resolution
package shared

import (
	"fmt"
	"os"
)

// GetInternalHostname returns the machine's hostname.
// If os.Hostname() fails, it returns "localhost".
func GetInternalHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	return hostname
}

// GetServiceAddrWithEnv returns a service address, checking environment variable first.
// Pattern: Check env var → fallback to hostname-based address
// This eliminates the duplicated "if env := os.Getenv(...)" pattern across the codebase.
//
// Usage:
//   GetServiceAddrWithEnv("VAULT_ADDR", GetVaultHTTPSAddr)
//   GetServiceAddrWithEnv("CONSUL_HTTP_ADDR", GetConsulAddr)
func GetServiceAddrWithEnv(envVar string, fallbackFunc func() string) string {
	if addr := os.Getenv(envVar); addr != "" {
		return addr
	}
	return fallbackFunc()
}

// GetNomadAddr returns the Nomad address using internal hostname resolution
func GetNomadAddr() string {
	hostname := GetInternalHostname()
	return fmt.Sprintf("http://%s:%d", hostname, PortNomad)
}

// GetConsulAddr returns the Consul address using internal hostname resolution
func GetConsulAddr() string {
	hostname := GetInternalHostname()
	return fmt.Sprintf("http://%s:%d", hostname, PortConsul)
}

// GetConsulAPIAddr returns the Consul API address using internal hostname resolution
func GetConsulAPIAddr() string {
	hostname := GetInternalHostname()
	return fmt.Sprintf("http://%s:%d", hostname, PortConsulAPI)
}

// GetMinioAddr returns the MinIO address using internal hostname resolution
func GetMinioAddr() string {
	hostname := GetInternalHostname()
	return fmt.Sprintf("http://%s:%d", hostname, PortMinio)
}

// GetMinioAPIAddr returns the MinIO API address using internal hostname resolution
func GetMinioAPIAddr() string {
	hostname := GetInternalHostname()
	return fmt.Sprintf("http://%s:%d", hostname, PortMinioAPI)
}

// GetVaultHTTPSAddr returns the Vault HTTPS address using internal hostname resolution
// Uses HTTPS (Vault standard for production)
func GetVaultHTTPSAddr() string {
	hostname := GetInternalHostname()
	return fmt.Sprintf("https://%s:%d", hostname, PortVault)
}

// GetVaultHTTPAddr returns the Vault HTTP address using internal hostname resolution
// Uses HTTP (for non-TLS setups only)
func GetVaultHTTPAddr() string {
	hostname := GetInternalHostname()
	return fmt.Sprintf("http://%s:%d", hostname, PortVault)
}

// GetServiceAddr returns a generic service address for any port
func GetServiceAddr(port int, useHTTPS bool) string {
	hostname := GetInternalHostname()
	protocol := "http"
	if useHTTPS {
		protocol = "https"
	}
	return fmt.Sprintf("%s://%s:%d", protocol, hostname, port)
}

// GetConsulHostPort returns the Consul host:port (no protocol) for config files
// Used in HCL configs where scheme is specified separately
func GetConsulHostPort() string {
	hostname := GetInternalHostname()
	return fmt.Sprintf("%s:%d", hostname, PortConsul)
}

// GetVaultHostPort returns the Vault host:port (no protocol) for config files
func GetVaultHostPort() string {
	hostname := GetInternalHostname()
	return fmt.Sprintf("%s:%d", hostname, PortVault)
}

// GetVaultClusterHostPort returns the Vault cluster host:port (no protocol)
func GetVaultClusterHostPort() string {
	hostname := GetInternalHostname()
	return fmt.Sprintf("%s:%d", hostname, PortVaultCluster)
}

// GetVaultClusterAddr returns the Vault cluster HTTPS address (for cluster_addr config)
// Uses port 8201 for Vault cluster communication
func GetVaultClusterAddr() string {
	hostname := GetInternalHostname()
	return fmt.Sprintf("https://%s:%d", hostname, PortVaultCluster)
}

// GetVaultAddrWithEnv returns Vault address, checking VAULT_ADDR env var first
// Replaces the common pattern: if addr := os.Getenv("VAULT_ADDR"); addr != "" { return addr }
func GetVaultAddrWithEnv() string {
	return GetServiceAddrWithEnv("VAULT_ADDR", GetVaultHTTPSAddr)
}

// GetConsulAddrWithEnv returns Consul address, checking CONSUL_HTTP_ADDR env var first
// Replaces the common pattern: if addr := os.Getenv("CONSUL_HTTP_ADDR"); addr != "" { return addr }
func GetConsulAddrWithEnv() string {
	return GetServiceAddrWithEnv("CONSUL_HTTP_ADDR", GetConsulAddr)
}

// GetNomadAddrWithEnv returns Nomad address, checking NOMAD_ADDR env var first
func GetNomadAddrWithEnv() string {
	return GetServiceAddrWithEnv("NOMAD_ADDR", GetNomadAddr)
}