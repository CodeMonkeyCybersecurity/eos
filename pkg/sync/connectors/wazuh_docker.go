package connectors

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/synctypes"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/dockerlistener"
	"github.com/docker/docker/client"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// WazuhDockerConnector configures the Wazuh DockerListener for container monitoring.
type WazuhDockerConnector struct{}

// NewWazuhDockerConnector constructs a Docker ↔ Wazuh connector instance.
func NewWazuhDockerConnector() *WazuhDockerConnector {
	return &WazuhDockerConnector{}
}

// Name identifies the connector.
func (c *WazuhDockerConnector) Name() string {
	return "WazuhDockerConnector"
}

// Description provides a human-readable summary of the connector behaviour.
func (c *WazuhDockerConnector) Description() string {
	return "Configures the Wazuh DockerListener to monitor local Docker containers"
}

// ServicePair returns the normalized service pair identifier.
func (c *WazuhDockerConnector) ServicePair() string {
	return "docker-wazuh"
}

// PreflightCheck validates Docker and Wazuh agent prerequisites before configuration.
func (c *WazuhDockerConnector) PreflightCheck(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	role := wazuh.DetectRole(rc)
	switch role {
	case wazuh.RoleNone:
		return eos_err.NewUserError("Wazuh not detected on this host. Install wazuh-agent before syncing Docker monitoring.")
	case wazuh.RoleManager:
		logger.Warn("Detected Wazuh manager; continuing with Docker listener configuration", zap.String("role", string(role)))
	default:
		logger.Info("Detected Wazuh role", zap.String("role", string(role)))
	}

	if os.Geteuid() != 0 {
		return eos_err.NewUserError("root privileges required to configure wazuh-agent Docker listener")
	}

	cli, err := docker.New(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize Docker client: %w", err)
	}
	defer cli.Close()

	if err := docker.Ping(rc.Ctx, cli); err != nil {
		return classifyDockerError(err)
	}

	if _, err := docker.ListContainers(rc.Ctx, cli, 1); err != nil {
		return classifyDockerError(err)
	}

	if _, err := os.Stat(shared.DockerListener); err != nil {
		return fmt.Errorf("DockerListener script not found at %s: %w", shared.DockerListener, err)
	}

	if err := checkService(rc.Ctx, "wazuh-agent"); err != nil {
		return fmt.Errorf("wazuh-agent service not available: %w", err)
	}

	logger.Info("Preflight checks passed for Wazuh Docker listener configuration")
	return nil
}

// CheckConnection reports the current listener configuration status.
func (c *WazuhDockerConnector) CheckConnection(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) (*synctypes.SyncState, error) {
	state := &synctypes.SyncState{}
	logger := otelzap.Ctx(rc.Ctx)

	cli, err := docker.New(rc.Ctx)
	if err == nil {
		state.Service1Installed = true
		defer cli.Close()

		if err := docker.Ping(rc.Ctx, cli); err == nil {
			state.Service1Running = true
			state.Service1Healthy = true
		}
	}

	if _, err := os.Stat(shared.DockerListener); err == nil {
		state.Service2Installed = true
	} else {
		state.Reason = fmt.Sprintf("DockerListener missing: %v", err)
	}

	if err := checkService(rc.Ctx, "wazuh-agent"); err == nil {
		state.Service2Running = true
		state.Service2Healthy = true
	}

	if err := dockerlistener.Verify(rc); err == nil {
		state.Connected = true
		state.Healthy = true
		state.ConfigurationComplete = true
		state.ConfigurationValid = true
		state.Reason = "DockerListener shebang points at managed venv"
	} else if state.Reason == "" {
		state.Reason = err.Error()
	}

	logger.Info("Connection state evaluated",
		zap.Bool("connected", state.Connected),
		zap.Bool("healthy", state.Healthy),
		zap.String("reason", state.Reason))

	return state, nil
}

// Backup captures the current DockerListener script so rollback can restore it.
func (c *WazuhDockerConnector) Backup(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) (*synctypes.BackupMetadata, error) {
	logger := otelzap.Ctx(rc.Ctx)

	backupDir, err := os.MkdirTemp("", "eos-wazuh-docker-")
	if err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	backupPath, err := dockerlistener.Backup(rc, backupDir)
	if err != nil {
		return nil, err
	}

	metadata := &synctypes.BackupMetadata{
		BackupDir: backupDir,
		BackupFiles: map[string]string{
			shared.DockerListener: backupPath,
		},
		Service2ConfigPath: shared.DockerListener,
		RestartRequired:    true,
	}

	logger.Info("DockerListener backup completed",
		zap.String("backup_dir", backupDir),
		zap.String("backup_file", backupPath))

	return metadata, nil
}

// Connect executes the listener setup workflow.
func (c *WazuhDockerConnector) Connect(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	if config.DryRun {
		logger.Info("[DRY RUN] Would configure Wazuh DockerListener",
			zap.Strings("planned_steps", []string{
				"validate Docker API connectivity via SDK",
				"apt update",
				"install python3-venv, python3-pip",
				"create python virtual environment",
				"install docker listener Python dependencies",
				"patch DockerListener shebang",
				"restart wazuh-agent",
			}))
		return nil
	}

	return dockerlistener.Setup(rc)
}

// Verify confirms the DockerListener is configured and the agent responds.
func (c *WazuhDockerConnector) Verify(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	if err := dockerlistener.Verify(rc); err != nil {
		return err
	}

	cli, err := docker.New(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize Docker client: %w", err)
	}
	defer cli.Close()

	if _, err := docker.ListContainers(rc.Ctx, cli, 1); err != nil {
		logger.Warn("docker container listing failed", zap.Error(err))
		return classifyDockerError(err)
	}

	logger.Info("Wazuh DockerListener verified successfully")
	return nil
}

// Rollback restores the backed-up DockerListener script and restarts the agent.
func (c *WazuhDockerConnector) Rollback(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig, backup *synctypes.BackupMetadata) error {
	if backup == nil {
		return fmt.Errorf("no backup metadata provided for rollback")
	}

	path, ok := backup.BackupFiles[shared.DockerListener]
	if !ok || path == "" {
		return fmt.Errorf("backup metadata missing DockerListener entry")
	}

	return dockerlistener.Restore(rc, path)
}

func classifyDockerError(err error) error {
	if client.IsErrConnectionFailed(err) {
		return fmt.Errorf("docker daemon not reachable: %w", err)
	}

	var opError *net.OpError
	if errors.As(err, &opError) {
		if errors.Is(opError.Err, os.ErrPermission) {
			return eos_err.NewUserError("permission denied connecting to Docker socket. Add wazuh-agent to the docker group or adjust socket ACLs")
		}
		if opError.Err != nil && strings.Contains(opError.Err.Error(), "permission denied") {
			return eos_err.NewUserError("permission denied connecting to Docker socket. Add wazuh-agent to the docker group or adjust socket ACLs")
		}
	}

	if strings.Contains(err.Error(), "permission denied") {
		return eos_err.NewUserError("permission denied connecting to Docker socket. Add wazuh-agent to the docker group or adjust socket ACLs")
	}

	if strings.Contains(err.Error(), "connection refused") {
		return fmt.Errorf("docker daemon not running or unreachable: %w", err)
	}

	if strings.Contains(err.Error(), "no such host") {
		return fmt.Errorf("docker host not found: %w", err)
	}

	return err
}

func checkService(ctx context.Context, name string) error {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(checkCtx, "systemctl", "is-active", name)
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}
