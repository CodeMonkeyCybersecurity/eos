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

// GetServiceAddr returns a generic service address for any port
func GetServiceAddr(port int, useHTTPS bool) string {
	hostname := GetInternalHostname()
	protocol := "http"
	if useHTTPS {
		protocol = "https"
	}
	return fmt.Sprintf("%s://%s:%d", protocol, hostname, port)
}

// Legacy port constants for migration reference
const (
	LegacyNomadPort     = 4646
	LegacyConsulPort    = 8500
	LegacyVaultPort     = 8200
	LegacySaltAPIPort   = 8000
	LegacyCaddyPort     = 2019
	LegacyAuthentikPort = 9000
)