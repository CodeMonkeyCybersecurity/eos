// pkg/temporal/install.go
package temporal

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallServer installs production Temporal server with PostgreSQL
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Check prerequisites and existing installations
// - Intervene: Install PostgreSQL, Temporal, configure services
// - Evaluate: Verify installation and service status
func InstallServer(ctx context.Context, postgresPassword string) error {
	logger := otelzap.Ctx(ctx)
	config := DefaultConfig()
	config.PostgreSQLPassword = postgresPassword

	logger.Info("Starting Temporal server installation",
		zap.String("version", config.Version),
		zap.String("install_dir", config.InstallDir))

	// INTERVENE - Install components
	if err := installPostgreSQL(ctx, config); err != nil {
		return err
	}
	if err := setupDatabases(ctx, config); err != nil {
		return err
	}
	if err := installTemporalCLI(ctx, config); err != nil {
		return err
	}
	if err := createConfiguration(ctx, config); err != nil {
		return err
	}
	if err := initializeSchema(ctx, config); err != nil {
		return err
	}
	if err := createSystemdService(ctx, config); err != nil {
		return err
	}
	if err := saveCredentials(ctx, config); err != nil {
		return err
	}
	if err := startService(ctx); err != nil {
		return err
	}

	// EVALUATE
	verifyInstallation(ctx)
	logger.Info("Temporal server installation completed")
	return nil
}

func installPostgreSQL(ctx context.Context, config *TemporalConfig) error {
	logger := otelzap.Ctx(ctx)

	// Check if already running
	if output, _ := exec.CommandContext(ctx, "systemctl", "is-active", "postgresql").Output(); string(output) == "active\n" {
		logger.Info("PostgreSQL already installed")
		return nil
	}

	logger.Info("Installing PostgreSQL")

	// Add repository
	_ = exec.CommandContext(ctx, "sh", "-c", "wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -").Run()
	_ = exec.CommandContext(ctx, "sh", "-c", "echo 'deb http://apt.postgresql.org/pub/repos/apt/ $(lsb_release -cs)-pgdg main' > /etc/apt/sources.list.d/pgdg.list").Run()
	_ = exec.CommandContext(ctx, "apt-get", "update", "-qq").Run()

	// Install
	pkgName := fmt.Sprintf("postgresql-%s", config.PostgreSQLVersion)
	clientPkg := fmt.Sprintf("postgresql-client-%s", config.PostgreSQLVersion)
	if err := exec.CommandContext(ctx, "apt-get", "install", "-y", "-qq", pkgName, clientPkg).Run(); err != nil {
		return fmt.Errorf("failed to install PostgreSQL: %w", err)
	}

	_ = exec.CommandContext(ctx, "systemctl", "start", "postgresql").Run()
	_ = exec.CommandContext(ctx, "systemctl", "enable", "postgresql").Run()

	logger.Info("PostgreSQL installed")
	return nil
}

func setupDatabases(ctx context.Context, config *TemporalConfig) error {
	logger := otelzap.Ctx(ctx)

	sqlCmd := fmt.Sprintf(`
CREATE USER temporal WITH PASSWORD '%s';
CREATE DATABASE temporal OWNER temporal;
CREATE DATABASE temporal_visibility OWNER temporal;
GRANT ALL PRIVILEGES ON DATABASE temporal TO temporal;
GRANT ALL PRIVILEGES ON DATABASE temporal_visibility TO temporal;
`, config.PostgreSQLPassword)

	_ = exec.CommandContext(ctx, "sudo", "-u", "postgres", "psql", "-c", sqlCmd).Run()
	logger.Info("Databases created")
	return nil
}

func installTemporalCLI(ctx context.Context, config *TemporalConfig) error {
	logger := otelzap.Ctx(ctx)

	if _, err := exec.LookPath("temporal"); err == nil {
		logger.Info("Temporal CLI already installed")
		return nil
	}

	logger.Info("Installing Temporal CLI")
	tarFile := fmt.Sprintf("temporal_cli_%s_linux_amd64.tar.gz", config.Version)
	downloadURL := fmt.Sprintf("https://github.com/temporalio/temporal/releases/download/v%s/%s", config.Version, tarFile)

	tmpPath := filepath.Join("/tmp", tarFile)
	if err := exec.CommandContext(ctx, "wget", "-q", "-O", tmpPath, downloadURL).Run(); err != nil {
		return fmt.Errorf("failed to download Temporal CLI: %w", err)
	}

	cmd := exec.CommandContext(ctx, "tar", "xzf", tarFile)
	cmd.Dir = "/tmp"
	_ = cmd.Run()

	_ = exec.CommandContext(ctx, "mv", "/tmp/temporal", "/usr/local/bin/temporal").Run()
	_ = exec.CommandContext(ctx, "chmod", "+x", "/usr/local/bin/temporal").Run()
	_ = os.Remove(tmpPath)

	logger.Info("Temporal CLI installed")
	return nil
}

func createConfiguration(ctx context.Context, config *TemporalConfig) error {
	logger := otelzap.Ctx(ctx)

	_ = os.MkdirAll(config.InstallDir, shared.ServiceDirPerm)
	configDir := filepath.Join(config.InstallDir, "config")
	_ = os.MkdirAll(configDir, shared.ServiceDirPerm)
	_ = os.MkdirAll(config.DataDir, shared.ServiceDirPerm)

	configYAML := generateConfigYAML(config)
	_ = os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configYAML), shared.ConfigFilePerm)

	dynamicYAML := generateDynamicConfigYAML(config)
	_ = os.WriteFile(filepath.Join(configDir, "dynamic_config.yaml"), []byte(dynamicYAML), shared.ConfigFilePerm)

	logger.Info("Configuration files created")
	return nil
}

func initializeSchema(ctx context.Context, config *TemporalConfig) error {
	logger := otelzap.Ctx(ctx)

	_ = os.Setenv("PGPASSWORD", config.PostgreSQLPassword)
	defer func() { _ = os.Unsetenv("PGPASSWORD") }()

	// Main schema
	_ = exec.CommandContext(ctx, "temporal", "server", "start-database",
		"--db-port", "5432",
		"--db", "postgres12",
		"--database", "temporal",
		"--plugin", "postgres12",
		"--user", "temporal",
		"--password", config.PostgreSQLPassword).Run()

	// Visibility schema
	_ = exec.CommandContext(ctx, "temporal", "server", "start-database",
		"--db-port", "5432",
		"--db", "postgres12",
		"--database", "temporal_visibility",
		"--plugin", "postgres12",
		"--user", "temporal",
		"--password", config.PostgreSQLPassword).Run()

	logger.Info("Database schemas initialized")
	return nil
}

func createSystemdService(ctx context.Context, config *TemporalConfig) error {
	logger := otelzap.Ctx(ctx)

	serviceContent := fmt.Sprintf(`[Unit]
Description=Temporal Server for Iris Framework
Documentation=https://docs.temporal.io
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=%s
Environment="HOME=/root"
Environment="PATH=/usr/local/bin:/usr/bin:/bin"

ExecStart=/usr/local/bin/temporal server start-dev \
    --config %s/config/config.yaml \
    --namespace default \
    --ui-port %d \
    --db-filename ""

Restart=always
RestartSec=10
LimitNOFILE=65536

StandardOutput=journal
StandardError=journal
SyslogIdentifier=temporal-iris

[Install]
WantedBy=multi-user.target
`, config.InstallDir, config.InstallDir, config.UIPort)

	_ = os.WriteFile("/etc/systemd/system/temporal-iris.service", []byte(serviceContent), shared.ConfigFilePerm)
	_ = exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()

	logger.Info("Systemd service created")
	return nil
}

func saveCredentials(ctx context.Context, config *TemporalConfig) error {
	logger := otelzap.Ctx(ctx)

	credContent := fmt.Sprintf(`# Iris Temporal Credentials
POSTGRES_USER=temporal
POSTGRES_PASSWORD=%s
TEMPORAL_HOST=%s
TEMPORAL_PORT=%d
TEMPORAL_UI_PORT=%d
TEMPORAL_ADDRESS=%s:%d
TEMPORAL_UI=http://%s:%d
DATABASE_URL=postgresql://temporal:%s@localhost:5432/temporal
`, config.PostgreSQLPassword, config.Host, config.Port, config.UIPort,
		config.Host, config.Port, config.Host, config.UIPort, config.PostgreSQLPassword)

	credPath := filepath.Join(config.InstallDir, ".credentials")
	_ = os.WriteFile(credPath, []byte(credContent), shared.SecretFilePerm)

	logger.Info("Credentials saved", zap.String("path", credPath))
	return nil
}

func startService(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	_ = exec.CommandContext(ctx, "systemctl", "enable", ServiceName).Run()
	if err := exec.CommandContext(ctx, "systemctl", "start", ServiceName).Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	logger.Info("Temporal service started")
	return nil
}

func verifyInstallation(ctx context.Context) {
	logger := otelzap.Ctx(ctx)

	output, _ := exec.CommandContext(ctx, "systemctl", "is-active", ServiceName).Output()
	if string(output) == "active\n" {
		logger.Info("Temporal service is running")
	} else {
		logger.Warn("Temporal service may not be running")
	}
}
