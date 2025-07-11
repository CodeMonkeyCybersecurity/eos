package agents

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RunMapping executes the agent mapping process
// Migrated from cmd/create/delphi.go runMapping
func RunMapping(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check configuration and connectivity
	log.Info("Assessing Delphi configuration for agent mapping")
	
	cfg, err := delphi.ResolveConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to resolve config: %w", err)
	}

	log.Info("Using API",
		zap.String("endpoint", cfg.Endpoint),
		zap.String("port", cfg.Port))

	baseURL := fmt.Sprintf("%s://%s:%s", cfg.Protocol, cfg.Endpoint, cfg.Port)

	// INTERVENE - Fetch and process agent data
	log.Info("Fetching agents from API")
	
	agentsResp, err := FetchAgents(rc, baseURL, cfg.Token)
	if err != nil {
		return fmt.Errorf("failed to fetch agents: %w", err)
	}

	if len(agentsResp.Data.Agents) == 0 {
		log.Info("No agents found")
		return nil
	}

	log.Info("Found agents", zap.Int("count", len(agentsResp.Data.Agents)))

	for _, agent := range agentsResp.Data.Agents {
		PrintAgentInfo(agent)
		
		majorVersion, err := GetMajorVersion(agent.OS.Version)
		if err != nil {
			log.Warn("Could not parse version",
				zap.String("version", agent.OS.Version),
				zap.Error(err))
			continue
		}

		mappings := GetMappings(agent.OS.Name)
		pkgName := MatchPackage(mappings, agent.OS.Architecture, majorVersion)
		
		if pkgName != "" {
			fmt.Printf("    Package: %s\n", pkgName)
		} else {
			fmt.Printf("    Package: Not found (arch: %s, major: %d)\n", 
				agent.OS.Architecture, majorVersion)
		}
	}

	// EVALUATE - Log completion
	log.Info("Agent mapping completed successfully")
	return nil
}

// GetMappings returns package mappings for a distribution
// Migrated from cmd/create/delphi.go getMappings
func GetMappings(distribution string) []PackageMapping {
	switch strings.ToLower(distribution) {
	case "almalinux", "rocky":
		return []PackageMapping{
			{"almalinux", 8, "x86_64", "wazuh-agent-4.9.2-1.el8.x86_64.rpm"},
			{"almalinux", 9, "x86_64", "wazuh-agent-4.9.2-1.el9.x86_64.rpm"},
			{"rocky", 8, "x86_64", "wazuh-agent-4.9.2-1.el8.x86_64.rpm"},
			{"rocky", 9, "x86_64", "wazuh-agent-4.9.2-1.el9.x86_64.rpm"},
		}
	case "centos":
		return []PackageMapping{
			{"centos", 7, "x86_64", "wazuh-agent-4.9.2-1.el7.x86_64.rpm"},
			{"centos", 8, "x86_64", "wazuh-agent-4.9.2-1.el8.x86_64.rpm"},
		}
	default:
		return []PackageMapping{}
	}
}

// MatchPackage finds the appropriate package for given architecture and version
// Migrated from cmd/create/delphi.go matchPackage
func MatchPackage(mappings []PackageMapping, arch string, major int) string {
	for _, m := range mappings {
		if m.Major == major && strings.Contains(m.Arch, arch) {
			return m.Package
		}
	}
	return ""
}

// GetMajorVersion extracts the major version number from a version string
// Migrated from cmd/create/delphi.go getMajorVersion
func GetMajorVersion(versionStr string) (int, error) {
	parts := strings.Split(versionStr, ".")
	if len(parts) > 0 {
		return strconv.Atoi(parts[0])
	}
	return 0, fmt.Errorf("invalid version string: %s", versionStr)
}