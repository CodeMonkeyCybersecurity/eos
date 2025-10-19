// pkg/consul/config/hcl_parser.go
// HCL configuration parsing and comparison for idempotency

package config

import (
	"fmt"
	"regexp"
	"strings"
)

// ParsedHCL represents parsed Consul HCL configuration
type ParsedHCL struct {
	BindAddr   string
	RetryJoin  []string
	Encrypt    string
	Datacenter string
	RawContent string
}

var (
	hclBindAddrRegex   = regexp.MustCompile(`bind_addr\s*=\s*"([^"]+)"`)
	hclRetryJoinRegex  = regexp.MustCompile(`retry_join\s*=\s*\[([\s\S]*?)\]`)
	hclEncryptRegex    = regexp.MustCompile(`encrypt\s*=\s*"([^"]+)"`)
	hclDatacenterRegex = regexp.MustCompile(`datacenter\s*=\s*"([^"]+)"`)
)

// ParseHCL parses a Consul HCL configuration file
func ParseHCL(content string) (*ParsedHCL, error) {
	cfg := &ParsedHCL{
		RawContent: content,
		RetryJoin:  make([]string, 0),
	}

	// Parse bind_addr
	if match := hclBindAddrRegex.FindStringSubmatch(content); len(match) > 1 {
		cfg.BindAddr = match[1]
	}

	// Parse retry_join array
	if match := hclRetryJoinRegex.FindStringSubmatch(content); len(match) > 1 {
		joinBlock := match[1]
		// Extract IPs from lines like: "100.65.138.128", or "192.168.1.10",
		ipRegex := regexp.MustCompile(`"([^"]+)"`)
		for _, ipMatch := range ipRegex.FindAllStringSubmatch(joinBlock, -1) {
			if len(ipMatch) > 1 {
				ip := strings.TrimSpace(ipMatch[1])
				if ip != "" {
					cfg.RetryJoin = append(cfg.RetryJoin, ip)
				}
			}
		}
	}

	// Parse encrypt (gossip key)
	if match := hclEncryptRegex.FindStringSubmatch(content); len(match) > 1 {
		cfg.Encrypt = match[1]
	}

	// Parse datacenter
	if match := hclDatacenterRegex.FindStringSubmatch(content); len(match) > 1 {
		cfg.Datacenter = match[1]
	}

	return cfg, nil
}

// NeedsUpdate checks if configuration needs to be updated
// Returns true if bind_addr or retry_join differ from desired values
func NeedsUpdate(current *ParsedHCL, desiredBindAddr string, desiredRetryJoin []string) bool {
	// Check bind_addr
	if current.BindAddr != desiredBindAddr {
		return true
	}

	// Check retry_join - must have same IPs (order doesn't matter)
	if len(current.RetryJoin) != len(desiredRetryJoin) {
		return true
	}

	// Convert to sets for comparison
	currentSet := make(map[string]bool)
	for _, ip := range current.RetryJoin {
		currentSet[ip] = true
	}

	for _, ip := range desiredRetryJoin {
		if !currentSet[ip] {
			return true // Desired IP not in current config
		}
	}

	return false // All match
}

// ValidateEncryptKeyMatch checks if gossip encryption keys match across nodes
func ValidateEncryptKeyMatch(configs map[string]*ParsedHCL) error {
	if len(configs) == 0 {
		return nil
	}

	var firstKey string
	var firstName string

	for nodeName, cfg := range configs {
		if firstKey == "" {
			firstKey = cfg.Encrypt
			firstName = nodeName
			continue
		}

		if cfg.Encrypt != firstKey {
			return fmt.Errorf("gossip encryption key mismatch: %s has different key than %s\n"+
				"All cluster members must have the same encrypt value.\n"+
				"Fix: Ensure all nodes have matching 'encrypt' in consul.hcl",
				nodeName, firstName)
		}
	}

	return nil
}

// UpdateConfig updates the Consul configuration with new values
// Preserves non-Tailscale IPs in retry_join (mixed network support)
func UpdateConfig(existingConfig, bindAddr string, retryJoinAddrs []string, preserveNonTailscale bool) string {
	lines := strings.Split(existingConfig, "\n")
	var newLines []string
	inRetryJoinBlock := false
	foundBindAddr := false

	// If preserving non-Tailscale IPs, parse existing config first
	var existingNonTailscaleIPs []string
	if preserveNonTailscale {
		existing, _ := ParseHCL(existingConfig)
		for _, ip := range existing.RetryJoin {
			if !IsTailscaleIP(ip) {
				existingNonTailscaleIPs = append(existingNonTailscaleIPs, ip)
			}
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip existing retry_join lines
		if strings.HasPrefix(trimmed, "retry_join") {
			inRetryJoinBlock = true
			continue
		}
		if inRetryJoinBlock && (trimmed == "]" || trimmed == "") {
			inRetryJoinBlock = false
			continue
		}
		if inRetryJoinBlock {
			continue
		}

		// Update bind_addr
		if strings.HasPrefix(trimmed, "bind_addr") {
			newLines = append(newLines, fmt.Sprintf(`bind_addr = "%s"  # Tailscale IP`, bindAddr))
			foundBindAddr = true
			continue
		}

		newLines = append(newLines, line)
	}

	// Add bind_addr if not found
	if !foundBindAddr {
		newLines = append(newLines, "")
		newLines = append(newLines, fmt.Sprintf(`bind_addr = "%s"  # Tailscale IP`, bindAddr))
	}

	// Add retry_join configuration
	newLines = append(newLines, "")
	newLines = append(newLines, "# Cluster join configuration")
	newLines = append(newLines, "retry_join = [")
	for _, addr := range retryJoinAddrs {
		newLines = append(newLines, fmt.Sprintf(`  "%s",  # Tailscale peer`, addr))
	}
	for _, addr := range existingNonTailscaleIPs {
		newLines = append(newLines, fmt.Sprintf(`  "%s",  # Non-Tailscale (preserved)`, addr))
	}
	newLines = append(newLines, "]")

	return strings.Join(newLines, "\n")
}

// UpdateRetryJoin updates only the retry_join configuration
// Used by unsync to remove specific nodes from retry_join
func UpdateRetryJoin(existingConfig string, newRetryJoin []string) string {
	lines := strings.Split(existingConfig, "\n")
	var newLines []string
	inRetryJoinBlock := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip existing retry_join lines
		if strings.HasPrefix(trimmed, "retry_join") {
			inRetryJoinBlock = true
			continue
		}
		if inRetryJoinBlock && (trimmed == "]" || trimmed == "") {
			inRetryJoinBlock = false
			continue
		}
		if inRetryJoinBlock {
			continue
		}

		newLines = append(newLines, line)
	}

	// Add new retry_join configuration
	if len(newRetryJoin) > 0 {
		newLines = append(newLines, "")
		newLines = append(newLines, "# Cluster join configuration")
		newLines = append(newLines, "retry_join = [")
		for _, addr := range newRetryJoin {
			newLines = append(newLines, fmt.Sprintf(`  "%s",`, addr))
		}
		newLines = append(newLines, "]")
	}

	return strings.Join(newLines, "\n")
}

// IsTailscaleIP checks if an IP is in the Tailscale CGNAT range (100.64.0.0/10)
func IsTailscaleIP(ip string) bool {
	// Tailscale uses 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	if parts[0] != "100" {
		return false
	}

	// Second octet must be 64-127
	var second int
	_, err := fmt.Sscanf(parts[1], "%d", &second)
	if err != nil {
		return false
	}

	return second >= 64 && second <= 127
}
