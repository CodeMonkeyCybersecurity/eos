package inspect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// Inspector handles infrastructure discovery
type Inspector struct {
	rc *eos_io.RuntimeContext
}

// New creates a new infrastructure inspector
func New(rc *eos_io.RuntimeContext) *Inspector {
	return &Inspector{
		rc: rc,
	}
}

// runCommand executes a command and returns output
func (i *Inspector) runCommand(name string, args ...string) (string, error) {
	logger := otelzap.Ctx(i.rc.Ctx)
	start := time.Now()
	
	logger.Info("🔧 Running command",
		zap.String("command", name),
		zap.Strings("args", args),
		zap.Duration("timeout", 30*time.Second))

	ctx, cancel := context.WithTimeout(i.rc.Ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start)
	
	if err != nil {
		logger.Error("⚠️ Command failed",
			zap.String("command", name),
			zap.Error(err),
			zap.String("stderr", stderr.String()),
			zap.Duration("duration", duration))
		return "", fmt.Errorf("command %s failed: %w (stderr: %s)", name, err, stderr.String())
	}

	logger.Info("✅ Command completed",
		zap.String("command", name),
		zap.Duration("duration", duration),
		zap.Int("output_length", len(strings.TrimSpace(stdout.String()))))

	return strings.TrimSpace(stdout.String()), nil
}

// commandExists checks if a command is available
func (i *Inspector) commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// DiscoverSystem gathers system information
func (i *Inspector) DiscoverSystem() (*SystemInfo, error) {
	logger := otelzap.Ctx(i.rc.Ctx)
	logger.Info("📊 Starting system discovery")
	
	info := &SystemInfo{}

	// Hostname
	if output, err := i.runCommand("hostname"); err == nil {
		info.Hostname = output
	}

	// OS information
	if output, err := i.runCommand("lsb_release", "-d", "-s"); err == nil {
		info.OS = output
	}
	if output, err := i.runCommand("lsb_release", "-r", "-s"); err == nil {
		info.OSVersion = output
	}
	if output, err := i.runCommand("uname", "-r"); err == nil {
		info.Kernel = output
	}
	if output, err := i.runCommand("uname", "-m"); err == nil {
		info.Architecture = output
	}

	// Uptime
	if output, err := i.runCommand("uptime", "-p"); err == nil {
		info.Uptime = output
	}

	// CPU Information
	if output, err := i.runCommand("lscpu"); err == nil {
		info.CPU = i.parseCPUInfo(output)
	}

	// Memory Information
	if output, err := i.runCommand("free", "-h"); err == nil {
		info.Memory = i.parseMemoryInfo(output)
	}

	// Disk Information
	if output, err := i.runCommand("df", "-hT"); err == nil {
		info.Disks = i.parseDiskInfo(output)
	}

	// Network Information
	if output, err := i.runCommand("ip", "-j", "addr", "show"); err == nil {
		info.Networks = i.parseNetworkInfo(output)
	}

	// Routing Information
	if output, err := i.runCommand("ip", "-j", "route", "show"); err == nil {
		info.Routes = i.parseRouteInfo(output)
	}

	logger.Info("✅ System discovery completed",
		zap.String("hostname", info.Hostname),
		zap.String("os", info.OS))

	return info, nil
}

// parseCPUInfo parses lscpu output
func (i *Inspector) parseCPUInfo(output string) CPUInfo {
	info := CPUInfo{}
	
	for line := range strings.SplitSeq(output, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		
		switch key {
		case "Model name":
			info.Model = value
		case "CPU(s)":
			if v, err := strconv.Atoi(value); err == nil {
				info.Count = v
			}
		case "Core(s) per socket":
			if v, err := strconv.Atoi(value); err == nil {
				info.Cores = v
			}
		case "Thread(s) per core":
			if v, err := strconv.Atoi(value); err == nil {
				info.Threads = v
			}
		}
	}
	
	return info
}

// parseMemoryInfo parses free -h output
func (i *Inspector) parseMemoryInfo(output string) MemoryInfo {
	info := MemoryInfo{}
	
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		
		if strings.HasPrefix(fields[0], "Mem:") {
			info.Total = fields[1]
			info.Used = fields[2]
			info.Free = fields[3]
			info.Available = fields[6]
		} else if strings.HasPrefix(fields[0], "Swap:") {
			info.SwapTotal = fields[1]
			info.SwapUsed = fields[2]
		}
	}
	
	return info
}

// parseDiskInfo parses df -hT output
func (i *Inspector) parseDiskInfo(output string) []DiskInfo {
	var disks []DiskInfo
	lines := strings.Split(output, "\n")
	
	// Skip header
	if len(lines) > 1 {
		lines = lines[1:]
	}
	
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		
		// Skip virtual filesystems
		if strings.HasPrefix(fields[0], "/dev/") || fields[0] == "tmpfs" {
			disk := DiskInfo{
				Filesystem: fields[0],
				Type:       fields[1],
				Size:       fields[2],
				Used:       fields[3],
				Available:  fields[4],
				UsePercent: fields[5],
				MountPoint: fields[6],
			}
			disks = append(disks, disk)
		}
	}
	
	return disks
}

// parseNetworkInfo parses ip addr show JSON output
func (i *Inspector) parseNetworkInfo(output string) []NetworkInfo {
	var networks []NetworkInfo
	
	var interfaces []struct {
		Ifname   string `json:"ifname"`
		Link     struct {
			State string `json:"operstate"`
			MAC   string `json:"address"`
		} `json:"link"`
		AddrInfo []struct {
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
		MTU int `json:"mtu"`
	}
	
	if err := json.Unmarshal([]byte(output), &interfaces); err != nil {
		logger := otelzap.Ctx(i.rc.Ctx)
		logger.Warn("⚠️ Failed to parse network JSON", zap.Error(err))
		return networks
	}
	
	for _, iface := range interfaces {
		// Skip loopback
		if iface.Ifname == "lo" {
			continue
		}
		
		var ips []string
		for _, addr := range iface.AddrInfo {
			ips = append(ips, fmt.Sprintf("%s/%d", addr.Local, addr.PrefixLen))
		}
		
		network := NetworkInfo{
			Interface: iface.Ifname,
			State:     iface.Link.State,
			MAC:       iface.Link.MAC,
			IPs:       ips,
			MTU:       iface.MTU,
		}
		networks = append(networks, network)
	}
	
	return networks
}

// parseRouteInfo parses ip route show JSON output
func (i *Inspector) parseRouteInfo(output string) []RouteInfo {
	var routes []RouteInfo
	
	var jsonRoutes []struct {
		Dst      string `json:"dst"`
		Gateway  string `json:"gateway"`
		Dev      string `json:"dev"`
		Metric   int    `json:"metric"`
	}
	
	if err := json.Unmarshal([]byte(output), &jsonRoutes); err != nil {
		logger := otelzap.Ctx(i.rc.Ctx)
		logger.Warn("⚠️ Failed to parse route JSON", zap.Error(err))
		return routes
	}
	
	for _, route := range jsonRoutes {
		r := RouteInfo{
			Destination: route.Dst,
			Gateway:     route.Gateway,
			Interface:   route.Dev,
			Metric:      route.Metric,
		}
		if r.Destination == "" {
			r.Destination = "default"
		}
		routes = append(routes, r)
	}
	
	return routes
}