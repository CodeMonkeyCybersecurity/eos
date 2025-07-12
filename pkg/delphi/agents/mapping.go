package agents

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi/utils"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RunMapping executes the agent mapping process
// Migrated from cmd/create/delphi.go runMapping
func RunMapping(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check configuration and connectivity
	log.Info("🔍 Assessing Delphi configuration for agent mapping")

	cfg, err := delphi.ResolveConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to resolve config: %w", err)
	}

	log.Info("📊 Using API",
		zap.String("fqdn", cfg.FQDN),
		zap.String("port", utils.DefaultStr(cfg.Port, "55000")))

	baseURL := fmt.Sprintf("%s://%s:%s",
		utils.DefaultStr(cfg.Protocol, "https"),
		cfg.FQDN,
		utils.DefaultStr(cfg.Port, "55000"))

	// INTERVENE - Fetch and process agent data
	log.Info("🚀 Fetching agents from API")

	// Authenticate first
	token, err := delphi.Authenticate(rc, cfg)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	agentsResp, err := FetchAgents(rc, baseURL, token)
	if err != nil {
		return fmt.Errorf("failed to fetch agents: %w", err)
	}

	if len(agentsResp.Data.AffectedItems) == 0 {
		log.Info("📭 No agents found")
		return nil
	}

	log.Info("📋 Found agents", zap.Int("count", len(agentsResp.Data.AffectedItems)))

	for _, agent := range agentsResp.Data.AffectedItems {
		PrintAgentInfo(agent)

		majorVersion, err := GetMajorVersion(agent.OS.Version)
		if err != nil {
			log.Warn("Could not parse version",
				zap.String("version", agent.OS.Version),
				zap.Error(err))
			continue
		}

		mappings := GetMappings(agent.OS.Name)
		if mappings == nil {
			fmt.Printf("❓ No mapping for distribution: %s\n", agent.OS.Name)
			continue
		}

		pkgName := MatchPackage(mappings, strings.ToLower(agent.OS.Architecture), majorVersion)

		if pkgName != "" {
			fmt.Printf(" Recommended package: %s\n", pkgName)
		} else {
			fmt.Printf("❌ No suitable package for version %s (%s)\n",
				agent.OS.Version, agent.OS.Architecture)
		}
	}

	// EVALUATE - Log completion
	log.Info(" Agent mapping completed successfully")
	return nil
}

// GetMappings returns package mappings for a distribution
// Migrated from cmd/create/delphi.go getMappings
func GetMappings(distribution string) []PackageMapping {
	switch strings.ToLower(distribution) {
	case "centos":
		return []PackageMapping{
			{"centos", 7, "x86_64", "wazuh-agent-4.11.0-1.x86_64.rpm"},
			{"centos", 7, "i386", "wazuh-agent-4.11.0-1.i386.rpm"},
			{"centos", 7, "aarch64", "wazuh-agent-4.11.0-1.aarch64.rpm"},
			{"centos", 7, "armhf", "wazuh-agent-4.11.0-1.armv7hl.rpm"},
		}
	case "debian":
		return []PackageMapping{
			{"debian", 8, "amd64", "wazuh-agent_4.11.0-1_amd64.deb"},
			{"debian", 8, "i386", "wazuh-agent_4.11.0-1_i386.deb"},
		}
	case "ubuntu":
		return []PackageMapping{
			{"ubuntu", 13, "amd64", "wazuh-agent_4.11.0-1_amd64.deb"},
			{"ubuntu", 13, "i386", "wazuh-agent_4.11.0-1_i386.deb"},
		}
	default:
		return nil
	}
}

// MatchPackage finds the appropriate package for given architecture and version
// Migrated from cmd/create/delphi.go matchPackage
func MatchPackage(mappings []PackageMapping, arch string, major int) string {
	for _, m := range mappings {
		if m.Arch == arch && major >= m.MinVersion {
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
