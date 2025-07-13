package network

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TailscalePeer represents a peer in the Tailscale network
type TailscalePeer struct {
	HostName       string `json:"HostName"`
	DNSName        string `json:"DNSName"`
	TailAddr       string `json:"TailAddr"`
	ID             string `json:"ID"`
	UserID         string `json:"UserID"`
	Online         bool   `json:"Online"`
	ExitNode       bool   `json:"ExitNode"`
	ExitNodeOption bool   `json:"ExitNodeOption"`
}

// TailscaleNetworkStatus represents the full Tailscale network status
type TailscaleNetworkStatus struct {
	Version      string                   `json:"Version"`
	TUN          bool                     `json:"TUN"`
	BackendState string                   `json:"BackendState"`
	AuthURL      string                   `json:"AuthURL"`
	TailscaleIPs []string                 `json:"TailscaleIPs"`
	Self         TailscalePeer            `json:"Self"`
	Peer         map[string]TailscalePeer `json:"Peer"`
	User         map[string]interface{}   `json:"User"`
}

// HostsConfig represents configuration for hosts file generation
type HostsConfig struct {
	OutputFile      string   `json:"output_file"`
	Format          string   `json:"format"` // yaml, json, conf, hosts
	ExcludeOffline  bool     `json:"exclude_offline"`
	ExcludeSelf     bool     `json:"exclude_self"`
	IncludeComments bool     `json:"include_comments"`
	FilterHosts     []string `json:"filter_hosts"` // Only include these hosts
}

// GenerateTailscaleHostsConfig generates a hosts configuration file from Tailscale status
func GenerateTailscaleHostsConfig(rc *eos_io.RuntimeContext, config *HostsConfig) error {
	ctx, span := telemetry.Start(rc.Ctx, "GenerateTailscaleHostsConfig")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Generating Tailscale hosts configuration",
		zap.String("output_file", config.OutputFile),
		zap.String("format", config.Format))

	// Set defaults
	if config.OutputFile == "" {
		config.OutputFile = "/tmp/tailscale_hosts.conf"
	}
	if config.Format == "" {
		config.Format = "yaml"
	}

	// Get Tailscale status
	status, err := getTailscaleNetworkStatus(rc)
	if err != nil {
		return fmt.Errorf("failed to get Tailscale status: %w", err)
	}

	// Filter peers
	peers := filterPeers(status, config)

	// Generate content based on format
	var content string
	switch config.Format {
	case "yaml":
		content = generateYAMLHosts(peers, config)
	case "json":
		content = generateJSONHosts(peers, config)
	case "conf":
		content = generateConfHosts(peers, config)
	case "hosts":
		content = generateHostsFileFormat(peers, config)
	default:
		return fmt.Errorf("unsupported format: %s", config.Format)
	}

	// Write to file
	if err := os.WriteFile(config.OutputFile, []byte(content), 0644); err != nil {
		logger.Error("Failed to write hosts file", zap.Error(err))
		return fmt.Errorf("failed to write hosts file: %w", err)
	}

	logger.Info("Tailscale hosts configuration generated successfully",
		zap.String("file", config.OutputFile),
		zap.Int("peer_count", len(peers)))

	return nil
}

// getTailscaleNetworkStatus retrieves the current Tailscale network status
func getTailscaleNetworkStatus(rc *eos_io.RuntimeContext) (*TailscaleNetworkStatus, error) {
	ctx, span := telemetry.Start(rc.Ctx, "getTailscaleNetworkStatus")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Getting Tailscale network status")

	// Run tailscale status --json
	output, err := execute.Run(ctx, execute.Options{
		Command: "tailscale",
		Args:    []string{"status", "--json"},
		Capture: true,
	})
	if err != nil {
		logger.Error("Failed to get Tailscale status", zap.Error(err))
		return nil, fmt.Errorf("failed to get Tailscale status: %w", err)
	}

	// Parse JSON output
	var status TailscaleNetworkStatus
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		logger.Error("Failed to parse Tailscale status JSON", zap.Error(err))
		return nil, fmt.Errorf("failed to parse Tailscale status: %w", err)
	}

	logger.Info("Tailscale status retrieved",
		zap.String("backend_state", status.BackendState),
		zap.Int("peer_count", len(status.Peer)),
		zap.String("self_hostname", status.Self.HostName))

	return &status, nil
}

// filterPeers filters peers based on configuration
func filterPeers(status *TailscaleNetworkStatus, config *HostsConfig) []TailscalePeer {
	var peers []TailscalePeer

	// Get current hostname to exclude self if needed
	currentHostname, _ := os.Hostname()

	// Add peers
	for _, peer := range status.Peer {
		// Skip offline peers if configured
		if config.ExcludeOffline && !peer.Online {
			continue
		}

		// Skip self if configured
		if config.ExcludeSelf && (peer.HostName == currentHostname || peer.HostName == status.Self.HostName) {
			continue
		}

		// Filter by specific hosts if configured
		if len(config.FilterHosts) > 0 {
			found := false
			for _, filterHost := range config.FilterHosts {
				if strings.Contains(peer.HostName, filterHost) ||
					strings.Contains(peer.DNSName, filterHost) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		peers = append(peers, peer)
	}

	return peers
}

// generateYAMLHosts generates YAML format hosts configuration
func generateYAMLHosts(peers []TailscalePeer, config *HostsConfig) string {
	var content strings.Builder

	if config.IncludeComments {
		content.WriteString("# Tailscale Hosts Configuration\n")
		content.WriteString("# Generated automatically - do not edit manually\n\n")
	}

	for _, peer := range peers {
		content.WriteString("- hostname: ")
		content.WriteString(peer.HostName)
		content.WriteString("\n  ip: ")
		content.WriteString(peer.TailAddr)
		if peer.DNSName != "" && peer.DNSName != peer.HostName {
			content.WriteString("\n  dns_name: ")
			content.WriteString(peer.DNSName)
		}
		if config.IncludeComments {
			content.WriteString("\n  # online: ")
			if peer.Online {
				content.WriteString("true")
			} else {
				content.WriteString("false")
			}
		}
		content.WriteString("\n")
	}

	return content.String()
}

// generateJSONHosts generates JSON format hosts configuration
func generateJSONHosts(peers []TailscalePeer, config *HostsConfig) string {
	type HostEntry struct {
		Hostname string `json:"hostname"`
		IP       string `json:"ip"`
		DNSName  string `json:"dns_name,omitempty"`
		Online   bool   `json:"online,omitempty"`
	}

	var hosts []HostEntry
	for _, peer := range peers {
		entry := HostEntry{
			Hostname: peer.HostName,
			IP:       peer.TailAddr,
		}
		if peer.DNSName != "" && peer.DNSName != peer.HostName {
			entry.DNSName = peer.DNSName
		}
		if config.IncludeComments {
			entry.Online = peer.Online
		}
		hosts = append(hosts, entry)
	}

	// Marshal to JSON with indentation
	jsonData, _ := json.MarshalIndent(hosts, "", "  ")
	return string(jsonData)
}

// generateConfHosts generates configuration file format
func generateConfHosts(peers []TailscalePeer, config *HostsConfig) string {
	var content strings.Builder

	if config.IncludeComments {
		content.WriteString("# Tailscale Hosts Configuration\n")
		content.WriteString("# Generated automatically - do not edit manually\n\n")
	}

	for _, peer := range peers {
		if config.IncludeComments {
			content.WriteString(fmt.Sprintf("# %s", peer.HostName))
			if !peer.Online {
				content.WriteString(" (offline)")
			}
			content.WriteString("\n")
		}
		content.WriteString(fmt.Sprintf("%s %s", peer.TailAddr, peer.HostName))
		if peer.DNSName != "" && peer.DNSName != peer.HostName {
			content.WriteString(" " + peer.DNSName)
		}
		content.WriteString("\n")
	}

	return content.String()
}

// generateHostsFileFormat generates /etc/hosts file format
func generateHostsFileFormat(peers []TailscalePeer, config *HostsConfig) string {
	var content strings.Builder

	if config.IncludeComments {
		content.WriteString("# Tailscale Hosts - Generated automatically\n")
	}

	for _, peer := range peers {
		if config.IncludeComments && !peer.Online {
			content.WriteString("# OFFLINE: ")
		}
		content.WriteString(fmt.Sprintf("%s\t%s", peer.TailAddr, peer.HostName))
		if peer.DNSName != "" && peer.DNSName != peer.HostName {
			content.WriteString(fmt.Sprintf("\t%s", peer.DNSName))
		}
		content.WriteString("\n")
	}

	return content.String()
}

// DisplayTailscaleStatus displays the current Tailscale network status
func DisplayTailscaleStatus(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "DisplayTailscaleStatus")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Displaying Tailscale network status")

	status, err := getTailscaleNetworkStatus(rc)
	if err != nil {
		return err
	}

	// Display overview
	logger.Info("=== Tailscale Network Status ===")
	logger.Info("Version", zap.String("version", status.Version))
	logger.Info("Backend State", zap.String("state", status.BackendState))
	logger.Info("TUN Interface", zap.Bool("enabled", status.TUN))

	if len(status.TailscaleIPs) > 0 {
		logger.Info("Tailscale IPs", zap.Strings("ips", status.TailscaleIPs))
	}

	// Display self information
	logger.Info("\n=== Self ===")
	logger.Info("Hostname", zap.String("hostname", status.Self.HostName))
	logger.Info("DNS Name", zap.String("dns_name", status.Self.DNSName))
	logger.Info("IP Address", zap.String("ip", status.Self.TailAddr))
	logger.Info("Online", zap.Bool("online", status.Self.Online))
	logger.Info("Exit Node", zap.Bool("exit_node", status.Self.ExitNode))

	// Display peers
	logger.Info("\n=== Peers ===")
	if len(status.Peer) == 0 {
		logger.Info("No peers found")
	} else {
		for _, peer := range status.Peer {
			logger.Info(fmt.Sprintf("Peer: %s", peer.HostName),
				zap.String("ip", peer.TailAddr),
				zap.String("dns_name", peer.DNSName),
				zap.Bool("online", peer.Online),
				zap.Bool("exit_node", peer.ExitNode))
		}
	}

	return nil
}

// GetTailscaleHostsForAnsible generates an Ansible inventory from Tailscale peers
func GetTailscaleHostsForAnsible(rc *eos_io.RuntimeContext, outputFile string) error {
	ctx, span := telemetry.Start(rc.Ctx, "GetTailscaleHostsForAnsible")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Generating Ansible inventory from Tailscale hosts")

	status, err := getTailscaleNetworkStatus(rc)
	if err != nil {
		return err
	}

	var content strings.Builder
	content.WriteString("[tailscale_hosts]\n")

	for _, peer := range status.Peer {
		if peer.Online {
			content.WriteString(fmt.Sprintf("%s ansible_host=%s\n", peer.HostName, peer.TailAddr))
		}
	}

	content.WriteString("\n[tailscale_hosts:vars]\n")
	content.WriteString("ansible_user=ubuntu\n")
	content.WriteString("ansible_ssh_common_args='-o StrictHostKeyChecking=no'\n")

	if outputFile == "" {
		outputFile = "/tmp/tailscale_inventory.ini"
	}

	if err := os.WriteFile(outputFile, []byte(content.String()), 0644); err != nil {
		return fmt.Errorf("failed to write Ansible inventory: %w", err)
	}

	logger.Info("Ansible inventory generated", zap.String("file", outputFile))
	return nil
}

var (
	hostsOutputFile      string
	hostsFormat          string
	hostsExcludeOffline  bool
	hostsExcludeSelf     bool
	hostsIncludeComments bool
	hostsFilterHosts     []string
	generateAnsible      bool
)

func RunCreateTailscaleHosts(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating Tailscale hosts configuration")

	// Handle Ansible inventory generation
	if generateAnsible {
		outputFile := hostsOutputFile
		if outputFile == "" {
			outputFile = "/tmp/tailscale_inventory.ini"
		}
		return GetTailscaleHostsForAnsible(rc, outputFile)
	}

	// Create configuration
	config := &HostsConfig{
		OutputFile:      hostsOutputFile,
		Format:          hostsFormat,
		ExcludeOffline:  hostsExcludeOffline,
		ExcludeSelf:     hostsExcludeSelf,
		IncludeComments: hostsIncludeComments,
		FilterHosts:     hostsFilterHosts,
	}

	// Generate hosts configuration
	if err := GenerateTailscaleHostsConfig(rc, config); err != nil {
		logger.Error("Failed to generate Tailscale hosts configuration", zap.Error(err))
		return err
	}

	logger.Info("Tailscale hosts configuration generated successfully",
		zap.String("output_file", config.OutputFile),
		zap.String("format", config.Format))

	return nil
}
