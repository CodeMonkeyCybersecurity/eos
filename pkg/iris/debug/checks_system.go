// pkg/iris/debug/checks_system.go
package debug

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckGoDependencies verifies that Go module dependencies are valid for worker and webhook
func CheckGoDependencies(rc *eos_io.RuntimeContext, projectDir string) CheckResult {
	err := validateGoDependencies(rc, projectDir)
	result := CheckResult{
		Name:     "Go Dependencies",
		Category: "Dependencies",
		Passed:   err == nil,
		Error:    err,
	}

	if err != nil {
		result.Remediation = []string{
			"Fix worker dependencies: cd /opt/iris/worker && go mod tidy",
			"Fix webhook dependencies: cd /opt/iris/webhook && go mod tidy",
			"Download modules: go mod download",
			"Verify Go installation: go version",
			"Check module cache: go clean -modcache",
			"If behind proxy, set GOPROXY environment variable",
		}
	} else {
		result.Details = "Worker and webhook dependencies verified"
	}

	return result
}

func validateGoDependencies(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check worker dependencies
	workerDir := filepath.Join(projectDir, "worker")
	if _, err := os.Stat(filepath.Join(workerDir, "go.mod")); os.IsNotExist(err) {
		return fmt.Errorf("worker/go.mod not found")
	}

	workerVerify := exec.CommandContext(rc.Ctx, "go", "mod", "verify")
	workerVerify.Dir = workerDir
	if output, err := workerVerify.CombinedOutput(); err != nil {
		logger.Debug("Worker go mod verify failed", zap.String("output", string(output)))
		return fmt.Errorf("worker dependencies invalid: %s", string(output))
	}

	// Check webhook dependencies
	webhookDir := filepath.Join(projectDir, "webhook")
	if _, err := os.Stat(filepath.Join(webhookDir, "go.mod")); os.IsNotExist(err) {
		return fmt.Errorf("webhook/go.mod not found")
	}

	webhookVerify := exec.CommandContext(rc.Ctx, "go", "mod", "verify")
	webhookVerify.Dir = webhookDir
	if output, err := webhookVerify.CombinedOutput(); err != nil {
		logger.Debug("Webhook go mod verify failed", zap.String("output", string(output)))
		return fmt.Errorf("webhook dependencies invalid: %s", string(output))
	}

	return nil
}
