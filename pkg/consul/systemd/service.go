package systemd

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateService creates the Consul systemd service unit file
// Migrated from cmd/create/consul.go createConsulSystemdService
func CreateService(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare service configuration
	log.Info("Assessing Consul systemd service requirements")

	// INTERVENE - Create systemd service file
	log.Info("Creating Consul systemd service")

	serviceContent := fmt.Sprintf(`[Unit]
Description=Consul Service Discovery and Configuration
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/consul.d/consul.hcl

[Service]
Type=notify
User=consul
Group=consul
ExecStart=/usr/local/bin/consul agent -config-dir=/etc/consul.d/
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/usr/local/bin/consul leave
KillMode=process
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
Environment="CONSUL_HTTP_ADDR=127.0.0.1:%d"

[Install]
WantedBy=multi-user.target`, shared.PortConsul)

	servicePath := "/etc/systemd/system/consul.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write systemd service: %w", err)
	}

	// Reload systemd
	if err := execute.RunSimple(rc.Ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// EVALUATE - Verify service file was created
	log.Info("Evaluating Consul systemd service creation")

	// Check if service file exists
	info, err := os.Stat(servicePath)
	if err != nil {
		return fmt.Errorf("failed to verify service file: %w", err)
	}

	if info.Mode().Perm() != 0644 {
		log.Warn("Service file permissions not as expected",
			zap.String("expected", "0644"),
			zap.String("actual", info.Mode().Perm().String()))
	}

	// Verify systemd recognizes the service
	checkCmd := execute.Options{
		Command: "systemctl",
		Args:    []string{"list-unit-files", "consul.service"},
		Capture: true, // Ensure we capture the output
	}
	output, err := execute.Run(rc.Ctx, checkCmd)
	if err != nil {
		log.Warn("systemctl list-unit-files failed, but service file exists",
			zap.Error(err),
			zap.String("output", output))
		// Don't fail here - service file exists and daemon-reload succeeded
		// TODO: Improve systemd service verification to be more robust
		return nil
	}

	if !strings.Contains(output, "consul.service") {
		log.Warn("systemd service not found in list-unit-files output",
			zap.String("output", output))
		// Don't fail here - service file exists and daemon-reload succeeded
		// TODO: Improve systemd service verification to be more robust
		return nil
	}

	log.Info("Consul systemd service created successfully",
		zap.String("path", servicePath),
		zap.Int("consul_port", shared.PortConsul))

	return nil
}
