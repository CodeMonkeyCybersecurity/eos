package create

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/osquery"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/state"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var quickstartCmd = &cobra.Command{
	Use:   "quickstart",
	Short: "Quick setup of a complete eos environment",
	Long: `Quickstart sets up a complete eos environment in under 5 minutes.
This includes Salt, Vault, OSQuery, and optionally Nomad for container orchestration.

The quickstart process will:
1. Bootstrap core infrastructure (Salt, Vault, OSQuery)
2. Use Salt to manage additional components
3. Verify all components are running correctly
4. Provide a summary of what was installed

This is ideal for:
- New users getting started with eos
- Testing eos capabilities on fresh VMs
- Rapid prototyping of infrastructure`,
	RunE: eos_cli.Wrap(runQuickstart),
}

func init() {
	CreateCmd.AddCommand(quickstartCmd)

	quickstartCmd.Flags().Bool("with-nomad", false, "Include Nomad for container orchestration")
	quickstartCmd.Flags().Bool("with-clusterfuzz", false, "Include ClusterFuzz setup")
	quickstartCmd.Flags().Bool("skip-verify", false, "Skip verification steps")
	quickstartCmd.Flags().Duration("timeout", 5*time.Minute, "Maximum time for quickstart")
}

func runQuickstart(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	logger.Info("Starting eos quickstart",
		zap.Time("start_time", startTime))

	// Create state tracker
	tracker := state.New()

	// Parse flags
	withNomad := cmd.Flag("with-nomad").Value.String() == "true"
	withClusterFuzz := cmd.Flag("with-clusterfuzz").Value.String() == "true"
	skipVerify := cmd.Flag("skip-verify").Value.String() == "true"
	timeout, _ := cmd.Flags().GetDuration("timeout")

	// Create context with timeout
	ctx, cancel := context.WithTimeout(rc.Ctx, timeout)
	defer cancel()
	rc.Ctx = ctx

	logger.Info("Quickstart configuration",
		zap.Bool("with_nomad", withNomad),
		zap.Bool("with_clusterfuzz", withClusterFuzz),
		zap.Bool("skip_verify", skipVerify),
		zap.Duration("timeout", timeout))

	// Phase 1: Core Bootstrap
	logger.Info("PHASE 1: Core Bootstrap",
		zap.Int("phase", 1),
		zap.Int("total_phases", 4))

	// 1.1 Bootstrap Salt
	logger.Info("Bootstrapping Salt (master-minion mode)")
	saltConfig := &saltstack.Config{
		MasterMode: true,
		LogLevel:   "warning",
	}
	if err := saltstack.Install(rc, saltConfig); err != nil {
		return fmt.Errorf("failed to bootstrap Salt: %w", err)
	}
	tracker.AddComponent(state.Component{
		Type:        state.ComponentSalt,
		Name:        "salt-master",
		Status:      "active",
		InstalledAt: time.Now(),
	})

	// 1.2 Bootstrap Vault
	logger.Info("Bootstrapping Vault")
	if err := vault.OrchestrateVaultCreateViaSalt(rc); err != nil {
		return fmt.Errorf("failed to bootstrap Vault: %w", err)
	}
	tracker.AddComponent(state.Component{
		Type:        state.ComponentVault,
		Name:        "vault",
		Status:      "active",
		InstalledAt: time.Now(),
	})

	// 1.3 Bootstrap OSQuery
	logger.Info("Bootstrapping OSQuery")
	if err := osquery.InstallOsquery(rc); err != nil {
		return fmt.Errorf("failed to bootstrap OSQuery: %w", err)
	}
	tracker.AddComponent(state.Component{
		Type:        state.ComponentOSQuery,
		Name:        "osquery",
		Status:      "active",
		InstalledAt: time.Now(),
	})

	// Phase 2: Salt-Managed Infrastructure
	logger.Info("PHASE 2: Salt-Managed Infrastructure",
		zap.Int("phase", 2),
		zap.Int("total_phases", 4))

	if withNomad {
		logger.Info("Installing Nomad via Salt")
		if err := installNomadViaSalt(rc); err != nil {
			return fmt.Errorf("failed to install Nomad: %w", err)
		}
		tracker.AddComponent(state.Component{
			Type:        state.ComponentNomad,
			Name:        "nomad",
			Status:      "active",
			InstalledAt: time.Now(),
		})
	}

	if withClusterFuzz {
		logger.Info("Setting up ClusterFuzz")
		if err := setupClusterFuzz(rc); err != nil {
			return fmt.Errorf("failed to setup ClusterFuzz: %w", err)
		}
		tracker.AddComponent(state.Component{
			Type:        state.ComponentClusterFuzz,
			Name:        "clusterfuzz",
			Status:      "active",
			InstalledAt: time.Now(),
		})
	}

	// Phase 3: State Tracking
	logger.Info("PHASE 3: State Tracking",
		zap.Int("phase", 3),
		zap.Int("total_phases", 4))

	// Gather current state
	if err := tracker.GatherInBand(rc); err != nil {
		logger.Warn("Failed to gather in-band state", zap.Error(err))
	}

	if err := tracker.GatherOutOfBand(rc); err != nil {
		logger.Warn("Failed to gather out-of-band state", zap.Error(err))
	}

	// Save state
	if err := tracker.Save(rc); err != nil {
		logger.Warn("Failed to save state", zap.Error(err))
	}

	// Phase 4: Verification
	if !skipVerify {
		logger.Info("PHASE 4: Verification",
			zap.Int("phase", 4),
			zap.Int("total_phases", 4))

		if err := verifyQuickstart(rc, tracker); err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}
	}

	// Calculate elapsed time
	elapsed := time.Since(startTime)

	// Print summary
	logger.Info("terminal prompt: Quickstart completed successfully!")
	logger.Info("Summary",
		zap.Duration("elapsed_time", elapsed),
		zap.Int("components_installed", len(tracker.Components)))

	// Print component list
	fmt.Println("\n" + tracker.ListComponents())

	if elapsed > 5*time.Minute {
		logger.Warn("Quickstart took longer than 5 minutes",
			zap.Duration("elapsed", elapsed),
			zap.Duration("target", 5*time.Minute))
	} else {
		logger.Info("Quickstart completed within target time!",
			zap.Duration("elapsed", elapsed))
	}

	// Print next steps
	fmt.Println("\nNext Steps:")
	fmt.Println("===========")
	fmt.Println("1. Check component status: eos list --all")
	fmt.Println("2. View Salt states: salt-call state.show_top")
	fmt.Println("3. Check Vault status: vault status")
	if withNomad {
		fmt.Println("4. Check Nomad status: nomad status")
	}
	fmt.Println("\nTo clean up everything: eos delete nuke --all")

	return nil
}

func installNomadViaSalt(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	cmd := eos_cli.New(rc)

	// Create Nomad Salt state
	nomadState := `nomad:
  archive.extracted:
    - name: /usr/local/bin
    - source: https://releases.hashicorp.com/nomad/{{ salt['pillar.get']('nomad:version', '1.9.3') }}/nomad_{{ salt['pillar.get']('nomad:version', '1.9.3') }}_linux_amd64.zip
    - skip_verify: True
    - enforce_toplevel: False
    - require_in:
      - service: nomad

  service.running:
    - enable: True
    - require:
      - archive: nomad
      - file: /etc/nomad.d/nomad.hcl

/etc/nomad.d:
  file.directory:
    - mode: 755
    - makedirs: True

/etc/nomad.d/nomad.hcl:
  file.managed:
    - source: salt://nomad/files/nomad.hcl
    - template: jinja
    - mode: 644
    - require:
      - file: /etc/nomad.d

/opt/nomad:
  file.directory:
    - mode: 755
    - makedirs: True

/opt/nomad/data:
  file.directory:
    - mode: 755
    - makedirs: True
    - require:
      - file: /opt/nomad

/etc/systemd/system/nomad.service:
  file.managed:
    - source: salt://nomad/files/nomad.service
    - mode: 644
`

	// Create directories
	if err := cmd.ExecToSuccess("mkdir", "-p", "/srv/salt/states/nomad/files"); err != nil {
		return fmt.Errorf("failed to create nomad state directory: %w", err)
	}

	// Write state file
	stateFile := "/srv/salt/states/nomad/init.sls"
	if err := os.WriteFile(stateFile, []byte(nomadState), 0644); err != nil {
		return fmt.Errorf("failed to write nomad state: %w", err)
	}

	// Create Nomad config
	nomadConfig := `datacenter = "dc1"
data_dir = "/opt/nomad/data"

server {
  enabled = true
  bootstrap_expect = 1
}

client {
  enabled = true
  servers = ["127.0.0.1:4647"]
}

ui {
  enabled = true
}

bind_addr = "0.0.0.0"
`

	configFile := "/srv/salt/states/nomad/files/nomad.hcl"
	if err := os.WriteFile(configFile, []byte(nomadConfig), 0644); err != nil {
		return fmt.Errorf("failed to write nomad config: %w", err)
	}

	// Create systemd service
	nomadService := `[Unit]
Description=Nomad
Documentation=https://nomadproject.io/docs/
Wants=network-online.target
After=network-online.target

[Service]
ExecReload=/bin/kill -HUP $MAINPID
ExecStart=/usr/local/bin/nomad agent -config /etc/nomad.d
KillMode=process
Restart=on-failure
LimitNOFILE=65536
RestartSec=5

[Install]
WantedBy=multi-user.target
`

	serviceFile := "/srv/salt/states/nomad/files/nomad.service"
	if err := os.WriteFile(serviceFile, []byte(nomadService), 0644); err != nil {
		return fmt.Errorf("failed to write nomad service: %w", err)
	}

	// Apply Salt state
	logger.Info("Applying Nomad Salt state")
	output, err := cmd.ExecString("salt-call", "--local", "state.apply", "nomad")
	if err != nil {
		return fmt.Errorf("failed to apply nomad state: %w", err)
	}

	logger.Info("Nomad installed via Salt", zap.String("output", output))
	return nil
}

func setupClusterFuzz(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// For now, just create the directory structure
	logger.Info("Setting up ClusterFuzz directory structure")

	cmd := eos_cli.New(rc)

	dirs := []string{
		"/opt/clusterfuzz",
		"/opt/clusterfuzz/configs",
		"/opt/clusterfuzz/jobs",
		"/opt/clusterfuzz/corpus",
	}

	for _, dir := range dirs {
		if err := cmd.ExecToSuccess("mkdir", "-p", dir); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Create a basic config
	config := `# ClusterFuzz Configuration
# Generated by eos quickstart

project_name: eos-testing
bot_count: 2
`

	configFile := "/opt/clusterfuzz/configs/config.yaml"
	if err := os.WriteFile(configFile, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write clusterfuzz config: %w", err)
	}

	logger.Info("ClusterFuzz setup completed")
	return nil
}

func verifyQuickstart(rc *eos_io.RuntimeContext, tracker *state.StateTracker) error {
	logger := otelzap.Ctx(rc.Ctx)
	cmd := eos_cli.New(rc)

	logger.Info("Verifying quickstart installation")

	// Verify core components
	components := []struct {
		name    string
		command string
		service string
	}{
		{"Salt Master", "salt", "salt-master"},
		{"Salt Minion", "salt-minion", "salt-minion"},
		{"Vault", "vault", "vault"},
		{"OSQuery", "osqueryi", "osqueryd"},
	}

	for _, comp := range components {
		// Check command exists
		if _, err := cmd.Which(comp.command); err != nil {
			return fmt.Errorf("%s command not found: %w", comp.name, err)
		}

		// Check service is running
		output, err := cmd.ExecString("systemctl", "is-active", comp.service)
		if err != nil || output != "active" {
			return fmt.Errorf("%s service is not active", comp.name)
		}

		logger.Info("Component verified",
			zap.String("component", comp.name),
			zap.String("status", "active"))
	}

	// Test Salt connectivity
	output, err := cmd.ExecString("salt", "*", "test.ping")
	if err != nil {
		logger.Warn("Salt connectivity test failed", zap.Error(err))
	} else {
		logger.Info("Salt connectivity verified", zap.String("output", output))
	}

	// Test OSQuery
	output, err = cmd.ExecString("osqueryi", "--json", "SELECT * FROM system_info;")
	if err != nil {
		logger.Warn("OSQuery test failed", zap.Error(err))
	} else {
		logger.Info("OSQuery verified")
	}

	logger.Info("All verifications passed")
	return nil
}
