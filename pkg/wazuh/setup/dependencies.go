// pkg/wazuh/setup/dependencies.go
// Python dependency management for Wazuh integration
//
// Created by Code Monkey Cybersecurity
// ABN: 77 177 673 061

package setup

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallPythonDependencies installs required Python packages for the integration
func InstallPythonDependencies(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	pythonBin := "/var/ossec/framework/python/bin/pip3"

	if _, err := os.Stat(pythonBin); os.IsNotExist(err) {
		return fmt.Errorf("Wazuh Python not found at %s", pythonBin)
	}

	dependencies := []string{"requests", "python-dotenv"}

	for _, dep := range dependencies {
		logger.Debug("Installing Python dependency", zap.String("package", dep))

		cmd := exec.Command(pythonBin, "install", dep)
		output, err := cmd.CombinedOutput()

		if err != nil {
			// Check if already installed
			if strings.Contains(string(output), "Requirement already satisfied") {
				logger.Debug("Python dependency already installed", zap.String("package", dep))
				continue
			}
			return fmt.Errorf("failed to install %s: %w\n%s", dep, err, string(output))
		}

		logger.Info("Python dependency installed", zap.String("package", dep))
	}

	return nil
}
