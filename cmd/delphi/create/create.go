// cmd/delphi/create/create.go
package create

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
)

var log = logger.L()

// CreateCmd is the root command for creation-related Delphi actions
var CreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create Delphi resources",
	Long:  "Create or generate Delphi-related resources, configurations, and mappings.",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log.Info("'eos delphi create' was called without a subcommand")
		return nil
	}),
}

var mappingCmd = &cobra.Command{
	Use:   "mapping",
	Short: "Suggest the best agent package for each endpoint",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		runMapping()
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

func runMapping() {
	cfg, err := delphi.ReadConfig(log)
	if err != nil {
		log.Fatal("Failed to load config", zap.Error(err))
	}

	cfg, err = delphi.ResolveConfig(log)
	if err != nil {
		log.Fatal("Failed to resolve Delphi config", zap.Error(err))
	}

	if cfg.Protocol == "" {
		cfg.Protocol = "https"
	}
	if cfg.Port == "" {
		cfg.Port = "55000"
	}

	apiURL := fmt.Sprintf("%s://%s:%s", cfg.Protocol, cfg.FQDN, cfg.Port)
	apiURL = strings.TrimRight(apiURL, "/")

	log.Info("Authenticating to Wazuh API", zap.String("url", apiURL))
	token, err := delphi.Authenticate(cfg, log)
	if err != nil {
		log.Fatal("Authentication failed", zap.Error(err))
	}

	agentsEndpoint := fmt.Sprintf("%s/agents?select=id,os,version", apiURL)
	req, err := http.NewRequest("GET", agentsEndpoint, nil)
	if err != nil {
		log.Fatal("Error creating request", zap.Error(err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Error making request", zap.Error(err))
	}
	defer shared.SafeClose(resp.Body, log)

	var agentsResp AgentsResponse
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&agentsResp); err != nil {
		log.Fatal("Failed to decode response", zap.Error(err))
	}

	for _, agent := range agentsResp.Data.AffectedItems {
		fmt.Printf("\nAgent %s:\n", agent.ID)
		fmt.Printf("  OS Name: %s\n", agent.OS.Name)
		fmt.Printf("  OS Version: %s\n", agent.OS.Version)
		fmt.Printf("  Architecture: %s\n", agent.OS.Architecture)

		mappings := getMappings(agent.OS.Name)
		if mappings == nil {
			fmt.Printf("  No package mapping available for distribution: %s\n", agent.OS.Name)
			continue
		}
		majorVer, err := getMajorVersion(agent.OS.Version)
		if err != nil {
			fmt.Printf("  Error parsing OS version: %v\n", err)
			continue
		}
		var found *PackageMapping
		archLower := strings.ToLower(agent.OS.Architecture)
		for _, m := range mappings {
			if archLower == m.Arch && majorVer >= m.MinVersion {
				found = &m
				break
			}
		}
		if found == nil {
			fmt.Printf("  No package mapping found for %s %s (%s)\n", agent.OS.Name, agent.OS.Version, agent.OS.Architecture)
		} else {
			fmt.Printf("  Appropriate package: %s\n", found.Package)
		}
	}
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
