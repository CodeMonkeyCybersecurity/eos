// pkg/environment/server_detection.go
// Reliable server role detection for distributed Eos deployments

package environment

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServerRole represents the detected role(s) of the current server
type ServerRole struct {
	// Primary roles
	IsHecateServer bool // Reverse proxy with Caddy/Authentik
	IsWazuhServer  bool // Wazuh SIEM backend
	IsConsulServer bool // Consul server
	IsVaultServer  bool // Vault server
	IsNomadServer  bool // Nomad server

	// Detected services (more granular)
	HasCaddy         bool
	HasAuthentik     bool
	HasNginx         bool
	HasWazuh         bool
	HasWazuhIndexer  bool
	HasWazuhDashboard bool
	HasConsul        bool
	HasVault         bool
	HasNomad         bool

	// Network detection
	Hostname       string
	TailscaleIP    string
	PublicIP       string
	HasTailscale   bool

	// Detection confidence
	DetectionMethod string // "filesystem", "process", "network", "consul"
	Confidence      string // "high", "medium", "low"
}

// ServerRoleRequirement specifies what a command needs
type ServerRoleRequirement struct {
	RequiredRoles []string // e.g., ["wazuh", "authentik"]
	AnyOf         bool     // true = need ANY role, false = need ALL roles
	ErrorMessage  string   // Custom error if requirement not met
}

// DetectServerRole performs comprehensive server role detection
func DetectServerRole(rc *eos_io.RuntimeContext) (*ServerRole, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Detecting server roles and capabilities")

	role := &ServerRole{}

	// Get hostname
	hostname, err := os.Hostname()
	if err == nil {
		role.Hostname = hostname
	}

	// ASSESS - Filesystem-based detection (highest confidence)
	detectFromFilesystem(role)

	// ASSESS - Process-based detection
	detectFromProcesses(rc, role)

	// ASSESS - Network-based detection
	detectFromNetwork(rc, role)

	// ASSESS - Consul-based detection (if available)
	detectFromConsul(rc, role)

	// EVALUATE - Determine primary roles
	determinePrimaryRoles(role)

	// EVALUATE - Assess confidence level
	role.Confidence = assessConfidence(role)

	logger.Info("Server role detection complete",
		zap.String("hostname", role.Hostname),
		zap.Bool("hecate_server", role.IsHecateServer),
		zap.Bool("wazuh_server", role.IsWazuhServer),
		zap.Bool("consul_server", role.IsConsulServer),
		zap.String("confidence", role.Confidence))

	return role, nil
}

// detectFromFilesystem checks for service-specific files/directories
func detectFromFilesystem(role *ServerRole) {
	checks := []struct {
		paths   []string
		handler func(*ServerRole)
	}{
		// Hecate/Caddy
		{
			paths: []string{
				"/opt/hecate/docker-compose.yml",
				"/opt/hecate/Caddyfile",
			},
			handler: func(r *ServerRole) {
				r.HasCaddy = true
			},
		},
		// Authentik
		{
			paths: []string{
				"/opt/hecate/authentik",
				"/opt/authentik",
			},
			handler: func(r *ServerRole) {
				r.HasAuthentik = true
			},
		},
		// Nginx
		{
			paths: []string{
				"/opt/hecate/assets/conf.d/stream",
				"/etc/nginx/nginx.conf",
			},
			handler: func(r *ServerRole) {
				r.HasNginx = true
			},
		},
		// Wazuh components
		{
			paths: []string{
				"/var/ossec/etc/ossec.conf",
				"/etc/wazuh-manager",
			},
			handler: func(r *ServerRole) {
				r.HasWazuh = true
			},
		},
		{
			paths: []string{
				"/etc/wazuh-indexer/opensearch.yml",
				"/etc/wazuh-indexer/opensearch-security/config.yml",
			},
			handler: func(r *ServerRole) {
				r.HasWazuhIndexer = true
			},
		},
		{
			paths: []string{
				"/etc/wazuh-dashboard/opensearch_dashboards.yml",
				"/usr/share/wazuh-dashboard",
			},
			handler: func(r *ServerRole) {
				r.HasWazuhDashboard = true
			},
		},
		// Consul
		{
			paths: []string{
				"/opt/consul/data",
				"/etc/consul.d/consul.hcl",
			},
			handler: func(r *ServerRole) {
				r.HasConsul = true
			},
		},
		// Vault
		{
			paths: []string{
				"/opt/vault/data",
				"/etc/vault.d/vault.hcl",
			},
			handler: func(r *ServerRole) {
				r.HasVault = true
			},
		},
		// Nomad
		{
			paths: []string{
				"/opt/nomad/data",
				"/etc/nomad.d/nomad.hcl",
			},
			handler: func(r *ServerRole) {
				r.HasNomad = true
			},
		},
	}

	for _, check := range checks {
		for _, path := range check.paths {
			if fileOrDirExists(path) {
				check.handler(role)
				role.DetectionMethod = "filesystem"
				break
			}
		}
	}
}

// detectFromProcesses checks running processes
func detectFromProcesses(rc *eos_io.RuntimeContext, role *ServerRole) {
	// This is a placeholder - full implementation would check:
	// - docker ps for container names
	// - systemctl status for services
	// - ps aux for process names
	// For now, filesystem detection is more reliable
}

// detectFromNetwork checks network configuration
func detectFromNetwork(rc *eos_io.RuntimeContext, role *ServerRole) {
	// Check for Tailscale
	if fileOrDirExists("/var/lib/tailscale") {
		role.HasTailscale = true
		// Could read Tailscale IP from: tailscale ip
	}
}

// detectFromConsul queries Consul for service catalog
func detectFromConsul(rc *eos_io.RuntimeContext, role *ServerRole) {
	// If Consul is available, query service catalog
	// This would provide highest confidence detection
	// TODO: Implement Consul API query
}

// determinePrimaryRoles sets the high-level role flags
func determinePrimaryRoles(role *ServerRole) {
	// Hecate server = has Caddy or Authentik in /opt/hecate
	role.IsHecateServer = role.HasCaddy || role.HasAuthentik

	// Wazuh server = has any Wazuh component
	role.IsWazuhServer = role.HasWazuh || role.HasWazuhIndexer || role.HasWazuhDashboard

	// Infrastructure servers
	role.IsConsulServer = role.HasConsul
	role.IsVaultServer = role.HasVault
	role.IsNomadServer = role.HasNomad
}

// assessConfidence determines detection confidence level
func assessConfidence(role *ServerRole) string {
	// High confidence if we detected via filesystem
	if role.DetectionMethod == "filesystem" {
		// Count how many services we detected
		count := 0
		if role.HasCaddy {
			count++
		}
		if role.HasAuthentik {
			count++
		}
		if role.HasWazuh {
			count++
		}
		if role.HasWazuhIndexer {
			count++
		}

		if count >= 2 {
			return "high"
		} else if count == 1 {
			return "medium"
		}
	}

	return "low"
}

// CheckRequirements validates server meets command requirements
func (r *ServerRole) CheckRequirements(req ServerRoleRequirement) error {
	if len(req.RequiredRoles) == 0 {
		return nil // No requirements
	}

	hasRoles := make(map[string]bool)
	hasRoles["hecate"] = r.IsHecateServer
	hasRoles["wazuh"] = r.IsWazuhServer
	hasRoles["consul"] = r.IsConsulServer
	hasRoles["vault"] = r.IsVaultServer
	hasRoles["nomad"] = r.IsNomadServer
	hasRoles["authentik"] = r.HasAuthentik
	hasRoles["caddy"] = r.HasCaddy

	if req.AnyOf {
		// Need at least ONE of the required roles
		for _, role := range req.RequiredRoles {
			if hasRoles[role] {
				return nil // Success
			}
		}

		// None of the required roles found
		if req.ErrorMessage != "" {
			return fmt.Errorf(req.ErrorMessage)
		}
		return fmt.Errorf("this command requires one of: %v\nDetected roles: %s",
			req.RequiredRoles, r.DescribeRoles())
	}

	// Need ALL of the required roles
	missing := []string{}
	for _, role := range req.RequiredRoles {
		if !hasRoles[role] {
			missing = append(missing, role)
		}
	}

	if len(missing) > 0 {
		if req.ErrorMessage != "" {
			return fmt.Errorf(req.ErrorMessage)
		}
		return fmt.Errorf("this command requires all of: %v\nMissing: %v\nDetected roles: %s",
			req.RequiredRoles, missing, r.DescribeRoles())
	}

	return nil
}

// DescribeRoles returns human-readable description of detected roles
func (r *ServerRole) DescribeRoles() string {
	roles := []string{}

	if r.IsHecateServer {
		components := []string{}
		if r.HasCaddy {
			components = append(components, "Caddy")
		}
		if r.HasAuthentik {
			components = append(components, "Authentik")
		}
		if r.HasNginx {
			components = append(components, "Nginx")
		}
		roles = append(roles, fmt.Sprintf("Hecate (%s)", strings.Join(components, ", ")))
	}

	if r.IsWazuhServer {
		components := []string{}
		if r.HasWazuh {
			components = append(components, "Manager")
		}
		if r.HasWazuhIndexer {
			components = append(components, "Indexer")
		}
		if r.HasWazuhDashboard {
			components = append(components, "Dashboard")
		}
		roles = append(roles, fmt.Sprintf("Wazuh (%s)", strings.Join(components, ", ")))
	}

	if r.IsConsulServer {
		roles = append(roles, "Consul")
	}
	if r.IsVaultServer {
		roles = append(roles, "Vault")
	}
	if r.IsNomadServer {
		roles = append(roles, "Nomad")
	}

	if len(roles) == 0 {
		return "no services detected"
	}

	return strings.Join(roles, ", ")
}

// GetServiceLocation returns where a service is expected to be
func (r *ServerRole) GetServiceLocation(service string) string {
	service = strings.ToLower(service)

	switch service {
	case "authentik":
		if r.HasAuthentik {
			return "local"
		}
		return "remote"
	case "wazuh":
		if r.HasWazuh || r.HasWazuhIndexer {
			return "local"
		}
		return "remote"
	case "consul":
		if r.HasConsul {
			return "local"
		}
		return "remote"
	case "vault":
		if r.HasVault {
			return "local"
		}
		return "remote"
	default:
		return "unknown"
	}
}

// fileOrDirExists checks if a file or directory exists
func fileOrDirExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
