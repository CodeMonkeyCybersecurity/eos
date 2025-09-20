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
	ComponentVault       ComponentType = "vault"
	ComponentNomad       ComponentType = "nomad"
	ComponentConsul      ComponentType = "consul"
	ComponentDocker      ComponentType = "docker"
	ComponentOSQuery     ComponentType = "osquery"
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
	Components   []Component `json:"components"`
	NomadJobs    []string    `json:"nomad_jobs"`
	SystemdUnits []string    `json:"systemd_units"`
	Packages     []string    `json:"packages"`
	Directories  []string    `json:"directories"`
	VaultMounts  []string    `json:"vault_mounts"`
	LastUpdated  time.Time   `json:"last_updated"`
}

// New creates a new StateTracker
func New() *StateTracker {
	return &StateTracker{
		Components:   []Component{},
		NomadJobs:    []string{},
		SystemdUnits: []string{},
		Packages:     []string{},
		Directories:  []string{},
		VaultMounts:  []string{},
		LastUpdated:  time.Now(),
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

// GatherOutOfBand gathers state using OSQuery and direct filesystem access
func (s *StateTracker) GatherOutOfBand(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Gathering out-of-band state information")

	cmd := eos_cli.New(rc)

	// Use OSQuery if available
	if _, err := cmd.Which("osqueryi"); err == nil {
		// Query for running processes
		query := `SELECT name, path, cmdline, pid FROM processes WHERE name IN ('-master', '-minion', 'vault', 'nomad', 'consul', 'docker', 'osqueryd');`

		if output, err := cmd.ExecString("osqueryi", "--json", query); err == nil {
			logger.Debug("OSQuery process data", zap.String("output", output))
			// Parse JSON and update component status
		}

		// Query for installed packages
		query = `SELECT name, version FROM deb_packages WHERE name IN ('vault', 'nomad', 'consul', 'docker-ce', 'osquery');`

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
		if strings.Contains(basename, "") || strings.Contains(basename, "vault") ||
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
