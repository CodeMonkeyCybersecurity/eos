// pkg/hecate/app_types.go

package hecate

import (
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// AppTypeDefaults defines the default configuration for an application type
type AppTypeDefaults struct {
	Name            string
	BackendProtocol string
	BackendPort     int
	BackendHost     string // For special cases like authentik
	TLSSkipVerify   bool
	WebSocket       bool
	HealthCheck     string
	LogLevel        string
	TCPPorts        map[int]int // external:backend
	SSOPublicPaths  []string
	DockerDeps      []string
	InternalOnly    bool // Backend is always internal docker
}

// AppTypes registry of all supported application types with their defaults
var AppTypes = map[string]AppTypeDefaults{
	"simple": {
		Name:            "simple",
		BackendProtocol: "http",
		BackendPort:     shared.PortHelen,
		HealthCheck:     "/",
		LogLevel:        "INFO",
	},

	"wazuh": {
		Name:            "wazuh",
		BackendProtocol: "https",
		BackendPort:     443,
		TLSSkipVerify:   true,
		LogLevel:        "DEBUG",
		HealthCheck:     "/",
		TCPPorts: map[int]int{
			1514:  1514,
			1515:  1515,
			55000: 55000,
		},
	},

	"nextcloud": {
		Name:            "nextcloud",
		BackendProtocol: "http",
		BackendPort:     shared.PortNextcloudLegacy,
		WebSocket:       true,
		HealthCheck:     "/status.php",
		LogLevel:        "INFO",
		SSOPublicPaths: []string{
			"/remote.php/dav",
			"/public.php",
			"/ocs/",
			"/status.php",
		},
	},

	"minio": {
		Name:            "minio",
		BackendProtocol: "http",
		BackendPort:     shared.PortMinio, // Console default
		HealthCheck:     "/minio/health/live",
		LogLevel:        "INFO",
	},

	"authentik": {
		Name:            "authentik",
		BackendProtocol: "http",
		BackendPort:     shared.PortAuthentik,
		BackendHost:     "hecate-server-1",
		WebSocket:       true,
		LogLevel:        "DEBUG",
		HealthCheck:     "/-/health/live/",
		DockerDeps:      []string{"postgresql", "redis"},
		InternalOnly:    true,
	},

	"grafana": {
		Name:            "grafana",
		BackendProtocol: "http",
		BackendPort:     shared.PortGrafana,
		HealthCheck:     "/api/health",
		LogLevel:        "INFO",
	},

	"umami": {
		Name:            "umami",
		BackendProtocol: "http",
		BackendPort:     shared.PortUmami,
		HealthCheck:     "/api/heartbeat",
		LogLevel:        "INFO",
	},

	"consul": {
		Name:            "consul",
		BackendProtocol: "http",
		BackendPort:     shared.PortConsul,
		HealthCheck:     "/v1/status/leader",
		LogLevel:        "INFO",
	},

	"vault": {
		Name:            "vault",
		BackendProtocol: "http",
		BackendPort:     shared.PortVault,
		HealthCheck:     "/v1/sys/health",
		LogLevel:        "INFO",
	},

	"jenkins": {
		Name:            "jenkins",
		BackendProtocol: "http",
		BackendPort:     shared.PortJenkins,
		HealthCheck:     "/login",
		LogLevel:        "INFO",
		TCPPorts: map[int]int{
			shared.PortJenkinsAgent: shared.PortJenkinsAgent,
		},
	},

	"mailcow": {
		Name:            "mailcow",
		BackendProtocol: "http",
		BackendPort:     shared.PortMailcow,
		HealthCheck:     "/",
		LogLevel:        "INFO",
		TCPPorts: map[int]int{
			shared.PortSMTP:       shared.PortSMTP,
			shared.PortSubmission: shared.PortSubmission,
			shared.PortSMTPS:      shared.PortSMTPS,
			shared.PortPOP3:       shared.PortPOP3,
			shared.PortPOP3SSL:    shared.PortPOP3SSL,
			shared.PortIMAP:       shared.PortIMAP,
			shared.PortIMAPSSL:    shared.PortIMAPSSL,
		},
	},
}

// DetectAppType infers app type from app name or explicit type
func DetectAppType(appName string, explicitType string) string {
	// Explicit type always wins
	if explicitType != "" {
		return explicitType
	}

	nameLower := strings.ToLower(appName)

	// Check for known service names
	if strings.Contains(nameLower, "wazuh") || strings.Contains(nameLower, "delphi") {
		return "wazuh"
	}
	if strings.Contains(nameLower, "nextcloud") || strings.Contains(nameLower, "cloud") {
		return "nextcloud"
	}
	if strings.Contains(nameLower, "minio") || strings.Contains(nameLower, "s3") {
		return "minio"
	}
	if strings.Contains(nameLower, "authentik") || nameLower == "auth" || nameLower == "hera" {
		return "authentik"
	}
	if strings.Contains(nameLower, "grafana") {
		return "grafana"
	}
	if strings.Contains(nameLower, "umami") {
		return "umami"
	}
	if strings.Contains(nameLower, "consul") {
		return "consul"
	}
	if strings.Contains(nameLower, "vault") {
		return "vault"
	}
	if strings.Contains(nameLower, "jenkins") {
		return "jenkins"
	}
	if strings.Contains(nameLower, "mailcow") || strings.Contains(nameLower, "mail") {
		return "mailcow"
	}

	return "simple"
}

// GetAppDefaults returns the default configuration for an app type
func GetAppDefaults(appType string) AppTypeDefaults {
	defaults, ok := AppTypes[appType]
	if !ok {
		// Return simple defaults if type not found
		return AppTypes["simple"]
	}
	return defaults
}
