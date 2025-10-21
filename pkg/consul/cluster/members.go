// pkg/consul/cluster/members.go
// Cluster member discovery and management

package cluster

import (
	"context"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Member represents a Consul cluster member
type Member struct {
	Name        string
	Address     string
	IP          string
	Port        string
	Status      string // alive, left, failed
	Type        string // server, client
	Datacenter  string
	IsTailscale bool
}

// MemberDiscoveryResult contains discovered members and metadata
type MemberDiscoveryResult struct {
	Members             []Member
	TailscaleMembers    []Member
	NonTailscaleMembers []Member
	HasMixedNetwork     bool
	AllAlive            bool
}

// DiscoverMembers discovers existing Consul cluster members
// Returns detailed member information with network classification
func DiscoverMembers(ctx context.Context, allowOffline bool) (*MemberDiscoveryResult, error) {
	logger := otelzap.Ctx(ctx)

	result := &MemberDiscoveryResult{
		Members:             make([]Member, 0),
		TailscaleMembers:    make([]Member, 0),
		NonTailscaleMembers: make([]Member, 0),
		AllAlive:            true,
	}

	// Get cluster members with detailed output
	output, err := execute.Run(ctx, execute.Options{
		Command: "consul",
		Args:    []string{"members", "-detailed"},
		Capture: true,
	})

	if err != nil {
		// If Consul isn't running yet, that's OK for first-time setup
		if strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(output, "connection refused") ||
			strings.Contains(err.Error(), "No such file") {
			logger.Debug("Consul not running - no existing members",
				zap.String("output", output))
			return result, nil
		}

		// Include actual command output in error for diagnostics
		return nil, fmt.Errorf("failed to discover cluster members: %w\n"+
			"Command output: %s\n"+
			"This is required for safe operation.\n"+
			"Check: sudo systemctl status consul\n"+
			"Fix: sudo eos fix consul\n"+
			"Debug: sudo eos debug consul", err, output)
	}

	lines := strings.Split(output, "\n")
	for i, line := range lines {
		// Skip header line
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		member := parseMemberLine(line)
		if member == nil {
			continue
		}

		// Classify member
		member.IsTailscale = config.IsTailscaleIP(member.IP)

		// Check status
		if member.Status != "alive" {
			result.AllAlive = false
			if !allowOffline {
				logger.Warn("Cluster member is not alive",
					zap.String("member", member.Name),
					zap.String("status", member.Status))
			}
		}

		// Add to appropriate lists
		result.Members = append(result.Members, *member)
		if member.IsTailscale {
			result.TailscaleMembers = append(result.TailscaleMembers, *member)
		} else {
			result.NonTailscaleMembers = append(result.NonTailscaleMembers, *member)
		}

		logger.Debug("Discovered cluster member",
			zap.String("name", member.Name),
			zap.String("ip", member.IP),
			zap.String("status", member.Status),
			zap.Bool("tailscale", member.IsTailscale))
	}

	// Detect mixed network environment
	result.HasMixedNetwork = len(result.TailscaleMembers) > 0 && len(result.NonTailscaleMembers) > 0

	if result.HasMixedNetwork {
		logger.Warn("Cluster has mixed network topology",
			zap.Int("tailscale_members", len(result.TailscaleMembers)),
			zap.Int("non_tailscale_members", len(result.NonTailscaleMembers)))
	}

	return result, nil
}

// parseMemberLine parses a single line from 'consul members -detailed' output
// Format: Node Address Status Type Build Protocol DC Partition Segment
func parseMemberLine(line string) *Member {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil
	}

	member := &Member{
		Name:    fields[0],
		Address: fields[1],
		Status:  fields[2],
	}

	// Parse type if available
	if len(fields) > 3 {
		member.Type = fields[3]
	}

	// Parse datacenter if available
	if len(fields) > 6 {
		member.Datacenter = fields[6]
	}

	// Extract IP and port from "IP:PORT" format
	parts := strings.Split(member.Address, ":")
	if len(parts) >= 1 {
		member.IP = parts[0]
	}
	if len(parts) >= 2 {
		member.Port = parts[1]
	}

	return member
}

// GetTailscaleIPs returns only Tailscale IPs from members
func (r *MemberDiscoveryResult) GetTailscaleIPs() []string {
	ips := make([]string, 0, len(r.TailscaleMembers))
	for _, member := range r.TailscaleMembers {
		ips = append(ips, member.IP)
	}
	return ips
}

// GetAllIPs returns all member IPs
func (r *MemberDiscoveryResult) GetAllIPs() []string {
	ips := make([]string, 0, len(r.Members))
	for _, member := range r.Members {
		ips = append(ips, member.IP)
	}
	return ips
}

// GetServerCount returns the number of server-type members
func (r *MemberDiscoveryResult) GetServerCount() int {
	count := 0
	for _, member := range r.Members {
		if member.Type == "server" {
			count++
		}
	}
	return count
}
