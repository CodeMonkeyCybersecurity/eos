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
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CommandTimeout is the maximum time a single shell command may run before
// being killed. Extracted as a constant per P0 Rule #12 (no hardcoded values).
// RATIONALE: 30 s is generous for docker/system commands but prevents hangs.
// SECURITY: Prevents unbounded resource consumption from stalled commands.
const CommandTimeout = 30 * time.Second

// CommandRunner abstracts shell command execution so the Inspector
// can be tested without a real Docker daemon or system utilities.
type CommandRunner interface {
	// Run executes name with args and returns trimmed stdout.
	Run(ctx context.Context, name string, args ...string) (string, error)
	// Exists reports whether name is available in PATH.
	Exists(name string) bool
}

// execRunner is the production CommandRunner backed by os/exec.
type execRunner struct{}

func (e *execRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, CommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("command %s failed: %w (stderr: %s)", name, err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

func (e *execRunner) Exists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Inspector handles infrastructure discovery.
type Inspector struct {
	rc     *eos_io.RuntimeContext
	runner CommandRunner
}

// New creates a new infrastructure inspector using the real os/exec runner.
func New(rc *eos_io.RuntimeContext) *Inspector {
	return &Inspector{
		rc:     rc,
		runner: &execRunner{},
	}
}

// NewWithRunner creates an Inspector with a custom CommandRunner.
// This is the primary testing seam.
func NewWithRunner(rc *eos_io.RuntimeContext, runner CommandRunner) *Inspector {
	return &Inspector{
		rc:     rc,
		runner: runner,
	}
}

// runCommand delegates to the CommandRunner with structured logging.
func (i *Inspector) runCommand(name string, args ...string) (string, error) {
	logger := otelzap.Ctx(i.rc.Ctx)
	start := time.Now()

	logger.Debug("Running command",
		zap.String("command", name),
		zap.Strings("args", args))

	output, err := i.runner.Run(i.rc.Ctx, name, args...)
	duration := time.Since(start)

	if err != nil {
		logger.Warn("Command failed",
			zap.String("command", name),
			zap.Error(err),
			zap.Duration("duration", duration))
		return "", err
	}

	logger.Debug("Command completed",
		zap.String("command", name),
		zap.Duration("duration", duration),
		zap.Int("output_bytes", len(output)))

	return output, nil
}

// commandExists checks if a command is available.
func (i *Inspector) commandExists(name string) bool {
	return i.runner.Exists(name)
}

// DiscoverSystem gathers system information.
func (i *Inspector) DiscoverSystem() (*SystemInfo, error) {
	logger := otelzap.Ctx(i.rc.Ctx)
	logger.Info("Starting system discovery")

	info := &SystemInfo{}

	if output, err := i.runCommand("hostname"); err == nil {
		info.Hostname = output
	}
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
	if output, err := i.runCommand("uptime", "-p"); err == nil {
		info.Uptime = output
	}
	if output, err := i.runCommand("lscpu"); err == nil {
		info.CPU = parseCPUInfo(output)
	}
	if output, err := i.runCommand("free", "-h"); err == nil {
		info.Memory = parseMemoryInfo(output)
	}
	if output, err := i.runCommand("df", "-hT"); err == nil {
		info.Disks = parseDiskInfo(output)
	}
	if output, err := i.runCommand("ip", "-j", "addr", "show"); err == nil {
		info.Networks = parseNetworkInfo(output)
	}
	if output, err := i.runCommand("ip", "-j", "route", "show"); err == nil {
		info.Routes = parseRouteInfo(output)
	}

	logger.Info("System discovery completed",
		zap.String("hostname", info.Hostname),
		zap.String("os", info.OS))

	return info, nil
}

// parseCPUInfo parses lscpu output. Pure function for testability.
func parseCPUInfo(output string) CPUInfo {
	info := CPUInfo{}
	for _, line := range strings.Split(output, "\n") {
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

// parseMemoryInfo parses free -h output. Pure function for testability.
// Mem line has 7 columns; Swap line has only 4 (total, used, free).
func parseMemoryInfo(output string) MemoryInfo {
	info := MemoryInfo{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if strings.HasPrefix(fields[0], "Mem:") && len(fields) >= 7 {
			info.Total = fields[1]
			info.Used = fields[2]
			info.Free = fields[3]
			info.Available = fields[6]
		} else if strings.HasPrefix(fields[0], "Swap:") && len(fields) >= 3 {
			info.SwapTotal = fields[1]
			info.SwapUsed = fields[2]
		}
	}
	return info
}

// parseDiskInfo parses df -hT output. Pure function for testability.
func parseDiskInfo(output string) []DiskInfo {
	var disks []DiskInfo
	lines := strings.Split(output, "\n")
	if len(lines) > 1 {
		lines = lines[1:] // skip header
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		if strings.HasPrefix(fields[0], "/dev/") || fields[0] == "tmpfs" {
			disks = append(disks, DiskInfo{
				Filesystem: fields[0],
				Type:       fields[1],
				Size:       fields[2],
				Used:       fields[3],
				Available:  fields[4],
				UsePercent: fields[5],
				MountPoint: fields[6],
			})
		}
	}
	return disks
}

// parseNetworkInfo parses ip -j addr show JSON output. Pure function for testability.
func parseNetworkInfo(output string) []NetworkInfo {
	var interfaces []struct {
		Ifname string `json:"ifname"`
		Link   struct {
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
		return nil
	}

	var networks []NetworkInfo
	for _, iface := range interfaces {
		if iface.Ifname == "lo" {
			continue
		}
		var ips []string
		for _, addr := range iface.AddrInfo {
			ips = append(ips, fmt.Sprintf("%s/%d", addr.Local, addr.PrefixLen))
		}
		networks = append(networks, NetworkInfo{
			Interface: iface.Ifname,
			State:     iface.Link.State,
			MAC:       iface.Link.MAC,
			IPs:       ips,
			MTU:       iface.MTU,
		})
	}
	return networks
}

// parseRouteInfo parses ip -j route show JSON output. Pure function for testability.
func parseRouteInfo(output string) []RouteInfo {
	var jsonRoutes []struct {
		Dst     string `json:"dst"`
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
		Metric  int    `json:"metric"`
	}
	if err := json.Unmarshal([]byte(output), &jsonRoutes); err != nil {
		return nil
	}

	var routes []RouteInfo
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
