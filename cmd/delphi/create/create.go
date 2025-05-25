// cmd/delphi/create/create.go
package create

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
)

// CreateCmd is the root command for creation-related Delphi actions
var CreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create Delphi resources",
	Long:  "Create or generate Delphi-related resources, configurations, and mappings.",
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		zap.L().Info("'eos delphi create' was called without a subcommand")
		return nil
	}),
}

var mappingCmd = &cobra.Command{
	Use:   "mapping",
	Short: "Suggest the best agent package for each endpoint",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		runMapping(rc.Ctx)
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(mappingCmd)
	CreateCmd.AddCommand(CreateJWTCmd)
}

type OSInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}

type Agent struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	OS      OSInfo `json:"os"`
}

type AgentsResponse struct {
	Data struct {
		AffectedItems []Agent `json:"affected_items"`
	} `json:"data"`
	Error   int    `json:"error"`
	Message string `json:"message"`
}

type PackageMapping struct {
	Distribution string
	MinVersion   int
	Arch         string
	Package      string
}

func runMapping(ctx context.Context) {
	cfg, err := delphi.ResolveConfig(ctx)
	if err != nil {
		zap.L().Fatal("Failed to resolve Delphi config", zap.Error(err))
	}

	baseURL := fmt.Sprintf("%s://%s:%s", defaultStr(cfg.Protocol, "https"), cfg.FQDN, defaultStr(cfg.Port, "55000"))
	token, err := delphi.Authenticate(cfg)
	if err != nil {
		zap.L().Fatal("Authentication failed", zap.Error(err))
	}

	resp, err := fetchAgents(baseURL, token)
	if err != nil {
		zap.L().Fatal("Failed to fetch agents", zap.Error(err))
	}

	for _, agent := range resp.Data.AffectedItems {
		printAgentInfo(agent)

		mappings := getMappings(agent.OS.Name)
		if mappings == nil {
			fmt.Printf("  ❌ No mapping for distribution: %s\n", agent.OS.Name)
			continue
		}

		major, err := getMajorVersion(agent.OS.Version)
		if err != nil {
			fmt.Printf("  ⚠️  Could not parse version: %v\n", err)
			continue
		}

		pkg := matchPackage(mappings, strings.ToLower(agent.OS.Architecture), major)
		if pkg == "" {
			fmt.Printf("  ❌ No suitable package for version %s (%s)\n", agent.OS.Version, agent.OS.Architecture)
		} else {
			fmt.Printf("  ✅ Recommended package: %s\n", pkg)
		}
	}
}

func fetchAgents(baseURL, token string) (*AgentsResponse, error) {
	url := strings.TrimRight(baseURL, "/") + "/agents?select=id,os,version"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP error: %w", err)
	}
	defer shared.SafeClose(resp.Body)

	var parsed AgentsResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode error: %w", err)
	}
	return &parsed, nil
}

func printAgentInfo(agent Agent) {
	fmt.Printf("\n🖥️ Agent %s:\n", agent.ID)
	fmt.Printf("  OS: %s %s (%s)\n", agent.OS.Name, agent.OS.Version, agent.OS.Architecture)
}

func matchPackage(mappings []PackageMapping, arch string, major int) string {
	for _, m := range mappings {
		if m.Arch == arch && major >= m.MinVersion {
			return m.Package
		}
	}
	return ""
}

func defaultStr(val, fallback string) string {
	if val == "" {
		return fallback
	}
	return val
}

func getMappings(distribution string) []PackageMapping {
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

func getMajorVersion(versionStr string) (int, error) {
	parts := strings.Split(versionStr, ".")
	return strconv.Atoi(parts[0])
}
