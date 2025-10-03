package network

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InterfaceInfo represents a network interface with routing information
type InterfaceInfo struct {
	Name    string
	IP      string
	Gateway string
	Metric  int
}

// GetPrimaryInterface finds the interface with the default route
// This is the most reliable indicator of the "primary" network
func GetPrimaryInterface() (*InterfaceInfo, error) {
	// Use 'ip route' to find default gateway
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get default route: %w", err)
	}

	// Parse: "default via 192.168.1.1 dev enp0s1 proto dhcp metric 100"
	line := strings.TrimSpace(string(output))
	if line == "" {
		return nil, fmt.Errorf("no default route found")
	}

	// Split and parse the route line
	parts := strings.Fields(line)
	var gateway, ifaceName string
	var metric int

	for i := 0; i < len(parts); i++ {
		switch parts[i] {
		case "via":
			if i+1 < len(parts) {
				gateway = parts[i+1]
			}
		case "dev":
			if i+1 < len(parts) {
				ifaceName = parts[i+1]
			}
		case "metric":
			if i+1 < len(parts) {
				metric, _ = strconv.Atoi(parts[i+1])
			}
		}
	}

	if ifaceName == "" {
		return nil, fmt.Errorf("could not parse interface name from route: %s", line)
	}

	// Get the IP address for this interface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for %s: %w", ifaceName, err)
	}

	var ip string
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			ip = ipnet.IP.String()
			break
		}
	}

	if ip == "" {
		return nil, fmt.Errorf("no IPv4 address found on %s", ifaceName)
	}

	return &InterfaceInfo{
		Name:    ifaceName,
		IP:      ip,
		Gateway: gateway,
		Metric:  metric,
	}, nil
}

// IsVirtualInterface checks if an interface is virtual/non-physical
func IsVirtualInterface(ifaceName string) bool {
	virtualPrefixes := []string{
		"docker",  // Docker bridge
		"virbr",   // libvirt/KVM bridge
		"veth",    // Virtual ethernet (containers)
		"br-",     // Docker custom bridges
		"lxc",     // LXC containers
		"tun",     // VPN tunnels
		"tap",     // VPN taps
		"wg",      // WireGuard VPN
		"tailscale", // Tailscale VPN
	}

	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(ifaceName, prefix) {
			return true
		}
	}

	// Check for loopback
	if ifaceName == "lo" {
		return true
	}

	return false
}

// GetAllViableInterfaces returns non-virtual interfaces with IPv4 addresses
func GetAllViableInterfaces() ([]*InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate interfaces: %w", err)
	}

	var viable []*InterfaceInfo
	for _, iface := range ifaces {
		// Skip down interfaces
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Skip virtual interfaces
		if IsVirtualInterface(iface.Name) {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				viable = append(viable, &InterfaceInfo{
					Name: iface.Name,
					IP:   ipnet.IP.String(),
				})
				break
			}
		}
	}

	return viable, nil
}

// SelectInterface intelligently selects the network interface to use
// Uses layered approach: auto-detect → filter → prompt
func SelectInterface(ctx *eos_io.RuntimeContext) (*InterfaceInfo, error) {
	log := otelzap.Ctx(ctx.Ctx)

	// ASSESS - Try automatic detection first (default gateway method)
	log.Info("Detecting primary network interface")
	primary, err := GetPrimaryInterface()
	if err == nil {
		log.Info("Auto-detected primary interface via default gateway",
			zap.String("interface", primary.Name),
			zap.String("ip", primary.IP),
			zap.String("gateway", primary.Gateway),
			zap.Int("metric", primary.Metric))
		return primary, nil
	}

	log.Warn("Could not auto-detect primary interface via default route",
		zap.Error(err))

	// ASSESS - Get all viable interfaces (filtering virtual ones)
	log.Info("Enumerating viable network interfaces")
	viable, err := GetAllViableInterfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate interfaces: %w", err)
	}

	if len(viable) == 0 {
		return nil, fmt.Errorf("no viable network interfaces found (only virtual/down interfaces present)")
	}

	if len(viable) == 1 {
		log.Info("Only one viable interface found, using it",
			zap.String("interface", viable[0].Name),
			zap.String("ip", viable[0].IP))
		return viable[0], nil
	}

	// INTERVENE - Multiple viable interfaces, prompt user
	log.Info("Multiple viable interfaces detected, prompting user",
		zap.Int("count", len(viable)))

	log.Info("terminal prompt: Select network interface")
	fmt.Println("\nMultiple network interfaces detected:")
	for i, iface := range viable {
		fmt.Printf("  %d. %s - %s\n", i+1, iface.Name, iface.IP)
	}

	selection, err := eos_io.PromptInput(ctx, fmt.Sprintf("Select interface number (1-%d)", len(viable)), "interface_selection")
	if err != nil {
		return nil, fmt.Errorf("failed to get interface selection: %w", err)
	}
	selectionNum, err := strconv.Atoi(selection)
	if err != nil || selectionNum < 1 || selectionNum > len(viable) {
		return nil, fmt.Errorf("invalid selection: %s (expected 1-%d)", selection, len(viable))
	}

	selected := viable[selectionNum-1]
	log.Info("User selected interface",
		zap.String("interface", selected.Name),
		zap.String("ip", selected.IP))

	return selected, nil
}
