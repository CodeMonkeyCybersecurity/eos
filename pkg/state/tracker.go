package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ComponentType represents the type of infrastructure component
type ComponentType string

const (
	ComponentSalt      ComponentType = "salt"
	ComponentVault     ComponentType = "vault"
	ComponentNomad     ComponentType = "nomad"
	ComponentConsul    ComponentType = "consul"
	ComponentDocker    ComponentType = "docker"
	ComponentOSQuery   ComponentType = "osquery"
	ComponentClusterFuzz ComponentType = "clusterfuzz"
)

// Component represents an infrastructure component managed by eos
type Component struct {
	Type        ComponentType `json:"type"`
	Name        string        `json:"name"`
	Version     string        `json:"version"`
	Status      string        `json:"status"`
	InstalledAt time.Time     `json:"installed_at"`
	Config      interface{}   `json:"config,omitempty"`
}

// StateTracker tracks all infrastructure components managed by eos
type StateTracker struct {
	Components    []Component `json:"components"`
	SaltStates    []string    `json:"salt_states"`
	NomadJobs     []string    `json:"nomad_jobs"`
	SystemdUnits  []string    `json:"systemd_units"`
	Packages      []string    `json:"packages"`
	Directories   []string    `json:"directories"`
	VaultMounts   []string    `json:"vault_mounts"`
	LastUpdated   time.Time   `json:"last_updated"`
}

// New creates a new StateTracker
func New() *StateTracker {
	return &StateTracker{
		Components:    []Component{},
		SaltStates:    []string{},
		NomadJobs:     []string{},
		SystemdUnits:  []string{},
		Packages:      []string{},
		Directories:   []string{},
		VaultMounts:   []string{},
		LastUpdated:   time.Now(),
	}
}

// Load loads state from disk
func Load(rc *eos_io.RuntimeContext) (*StateTracker, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	stateFile := "/var/lib/eos/state.json"
	
	// Create directory if it doesn't exist
	stateDir := filepath.Dir(stateFile)
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %w", err)
	}
	
	// Check if state file exists
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		logger.Info("State file does not exist, creating new tracker")
		return New(), nil
	}
	
	// Read state file
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}
	
	var tracker StateTracker
	if err := json.Unmarshal(data, &tracker); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}
	
	logger.Info("Loaded state from disk",
		zap.Int("components", len(tracker.Components)),
		zap.Time("last_updated", tracker.LastUpdated))
	
	return &tracker, nil
}

// Save saves state to disk
func (s *StateTracker) Save(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	s.LastUpdated = time.Now()
	
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}
	
	stateFile := "/var/lib/eos/state.json"
	if err := os.WriteFile(stateFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}
	
	logger.Info("Saved state to disk",
		zap.Int("components", len(s.Components)))
	
	return nil
}

// AddComponent adds a component to the tracker
func (s *StateTracker) AddComponent(comp Component) {
	// Check if component already exists
	for i, existing := range s.Components {
		if existing.Type == comp.Type && existing.Name == comp.Name {
			// Update existing component
			s.Components[i] = comp
			return
		}
	}
	
	// Add new component
	s.Components = append(s.Components, comp)
}

// GatherInBand gathers state using eos commands
func (s *StateTracker) GatherInBand(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Gathering in-band state information")
	
	cmd := eos_cli.New(rc)
	
	// Check for Salt
	if _, err := cmd.Which("salt"); err == nil {
		output, _ := cmd.ExecString("salt", "--version")
		s.AddComponent(Component{
			Type:        ComponentSalt,
			Name:        "salt-master",
			Version:     strings.TrimSpace(output),
			Status:      s.getServiceStatus(rc, "salt-master"),
			InstalledAt: time.Now(),
		})
		
		// Get Salt states
		if output, err := cmd.ExecString("salt-call", "--local", "state.show_top"); err == nil {
			// Parse output to extract state names
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "- ") {
					state := strings.TrimPrefix(line, "- ")
					s.SaltStates = append(s.SaltStates, state)
				}
			}
		}
	}
	
	// Check for Vault
	if _, err := cmd.Which("vault"); err == nil {
		output, _ := cmd.ExecString("vault", "version")
		s.AddComponent(Component{
			Type:        ComponentVault,
			Name:        "vault",
			Version:     strings.TrimSpace(output),
			Status:      s.getServiceStatus(rc, "vault"),
			InstalledAt: time.Now(),
		})
		
		// Get Vault mounts if accessible
		if os.Getenv("VAULT_TOKEN") != "" {
			if output, err := cmd.ExecString("vault", "secrets", "list", "-format=json"); err == nil {
				// Parse JSON to get mount points
				logger.Debug("Vault mounts retrieved", zap.String("output", output))
			}
		}
	}
	
	// Check for Nomad
	if _, err := cmd.Which("nomad"); err == nil {
		output, _ := cmd.ExecString("nomad", "version")
		s.AddComponent(Component{
			Type:        ComponentNomad,
			Name:        "nomad",
			Version:     strings.TrimSpace(output),
			Status:      s.getServiceStatus(rc, "nomad"),
			InstalledAt: time.Now(),
		})
		
		// Get Nomad jobs
		if output, err := cmd.ExecString("nomad", "job", "list", "-short"); err == nil {
			lines := strings.Split(output, "\n")
			for i, line := range lines {
				if i == 0 || line == "" {
					continue // Skip header
				}
				fields := strings.Fields(line)
				if len(fields) > 0 {
					s.NomadJobs = append(s.NomadJobs, fields[0])
				}
			}
		}
	}
	
	// Check for OSQuery
	if _, err := cmd.Which("osqueryi"); err == nil {
		output, _ := cmd.ExecString("osqueryi", "--version")
		s.AddComponent(Component{
			Type:        ComponentOSQuery,
			Name:        "osquery",
			Version:     strings.TrimSpace(output),
			Status:      s.getServiceStatus(rc, "osqueryd"),
			InstalledAt: time.Now(),
		})
	}
	
	// Get systemd units
	if output, err := cmd.ExecString("systemctl", "list-units", "--type=service", "--state=running", "--no-pager"); err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "salt") || strings.Contains(line, "vault") ||
			   strings.Contains(line, "nomad") || strings.Contains(line, "consul") ||
			   strings.Contains(line, "docker") || strings.Contains(line, "osquery") ||
			   strings.Contains(line, "eos-storage-monitor") || strings.Contains(line, "code-server") ||
			   strings.Contains(line, "prometheus") || strings.Contains(line, "grafana") ||
			   strings.Contains(line, "fail2ban") || strings.Contains(line, "trivy") ||
			   strings.Contains(line, "wazuh") || strings.Contains(line, "nginx") ||
			   strings.Contains(line, "glances") || strings.Contains(line, "hecate") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					s.SystemdUnits = append(s.SystemdUnits, fields[0])
				}
			}
		}
	}
	
	// Check key directories
	eosDirectories := []string{
		"/opt/eos",
		"/srv/salt",
		"/etc/salt",
		"/opt/vault",
		"/opt/nomad",
		"/etc/osquery",
		"/var/lib/eos",
	}
	
	for _, dir := range eosDirectories {
		if _, err := os.Stat(dir); err == nil {
			s.Directories = append(s.Directories, dir)
		}
	}
	
	logger.Info("In-band state gathering complete",
		zap.Int("components", len(s.Components)),
		zap.Int("salt_states", len(s.SaltStates)),
		zap.Int("nomad_jobs", len(s.NomadJobs)),
		zap.Int("systemd_units", len(s.SystemdUnits)),
		zap.Int("directories", len(s.Directories)))
	
	return nil
}

// GatherOutOfBand gathers state using OSQuery and direct filesystem access
func (s *StateTracker) GatherOutOfBand(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Gathering out-of-band state information")
	
	cmd := eos_cli.New(rc)
	
	// Use OSQuery if available
	if _, err := cmd.Which("osqueryi"); err == nil {
		// Query for running processes
		query := `SELECT name, path, cmdline, pid FROM processes WHERE name IN ('salt-master', 'salt-minion', 'vault', 'nomad', 'consul', 'docker', 'osqueryd');`
		
		if output, err := cmd.ExecString("osqueryi", "--json", query); err == nil {
			logger.Debug("OSQuery process data", zap.String("output", output))
			// Parse JSON and update component status
		}
		
		// Query for installed packages
		query = `SELECT name, version FROM deb_packages WHERE name IN ('salt-master', 'salt-minion', 'vault', 'nomad', 'consul', 'docker-ce', 'osquery');`
		
		if output, err := cmd.ExecString("osqueryi", "--json", query); err == nil {
			logger.Debug("OSQuery package data", zap.String("output", output))
			// Parse JSON and update packages list
		}
	}
	
	// Direct filesystem checks
	// Check for service files
	serviceFiles, _ := filepath.Glob("/etc/systemd/system/*.service")
	for _, file := range serviceFiles {
		basename := filepath.Base(file)
		if strings.Contains(basename, "salt") || strings.Contains(basename, "vault") ||
		   strings.Contains(basename, "nomad") || strings.Contains(basename, "consul") {
			s.SystemdUnits = append(s.SystemdUnits, basename)
		}
	}
	
	return nil
}

// getServiceStatus gets the status of a systemd service
func (s *StateTracker) getServiceStatus(rc *eos_io.RuntimeContext, service string) string {
	// Use execute directly to avoid error logging for inactive services
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", service},
		Capture: true,
	})
	if err != nil {
		// systemctl is-active returns exit code 3 for inactive services - this is normal
		return "inactive"
	}
	
	return strings.TrimSpace(output)
}

// ListComponents returns a formatted list of all components
func (s *StateTracker) ListComponents() string {
	if len(s.Components) == 0 {
		return "No components installed"
	}
	
	var result strings.Builder
	result.WriteString("Installed Components:\n")
	result.WriteString("====================\n\n")
	
	for _, comp := range s.Components {
		result.WriteString(fmt.Sprintf("%-12s %-20s %-15s %s\n",
			comp.Type,
			comp.Name,
			comp.Version,
			comp.Status))
	}
	
	if len(s.SaltStates) > 0 {
		result.WriteString("\nSalt States:\n")
		result.WriteString("============\n")
		for _, state := range s.SaltStates {
			result.WriteString(fmt.Sprintf("  - %s\n", state))
		}
	}
	
	if len(s.NomadJobs) > 0 {
		result.WriteString("\nNomad Jobs:\n")
		result.WriteString("===========\n")
		for _, job := range s.NomadJobs {
			result.WriteString(fmt.Sprintf("  - %s\n", job))
		}
	}
	
	if len(s.Directories) > 0 {
		result.WriteString("\nEos Directories:\n")
		result.WriteString("================\n")
		for _, dir := range s.Directories {
			result.WriteString(fmt.Sprintf("  - %s\n", dir))
		}
	}
	
	return result.String()
}