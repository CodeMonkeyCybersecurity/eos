package diagnostics

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CustomHooks runs custom diagnostic hooks
// Migrated from cmd/ragequit/ragequit.go customHooks
func CustomHooks(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check for custom hooks
	logger.Info("Assessing custom hooks requirements")

	hooksDir := "/etc/eos/ragequit-hooks"
	if !system.DirExists(hooksDir) {
		logger.Info("No custom hooks directory found, skipping")
		return nil
	}

	files, err := os.ReadDir(hooksDir)
	if err != nil {
		return fmt.Errorf("failed to read hooks directory: %w", err)
	}

	if len(files) == 0 {
		logger.Info("No custom hooks found in directory")
		return nil
	}

	homeDir := system.GetHomeDir()
	outputFile := filepath.Join(homeDir, "ragequit-custom.txt")

	var output strings.Builder
	output.WriteString("=== Custom Hooks Output ===\n")
	output.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format(time.RFC3339)))
	output.WriteString(fmt.Sprintf("Hooks directory: %s\n", hooksDir))

	// INTERVENE - Execute custom hooks
	logger.Debug("Executing custom hooks",
		zap.Int("hook_count", len(files)))

	executedCount := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		hookPath := filepath.Join(hooksDir, file.Name())
		if system.IsExecutable(hookPath) {
			logger.Debug("Executing custom hook",
				zap.String("hook", file.Name()))

			output.WriteString(fmt.Sprintf("\n--- Hook: %s ---\n", file.Name()))
			output.WriteString(fmt.Sprintf("Executed at: %s\n", time.Now().Format(time.RFC1123)))

			if hookOutput := system.RunCommandWithTimeout(hookPath, []string{}, 30*time.Second); hookOutput != "" {
				output.WriteString(hookOutput)
			} else {
				output.WriteString("(no output or timed out after 30s)\n")
			}
			output.WriteString("\n")
			executedCount++
		} else {
			logger.Debug("Skipping non-executable file",
				zap.String("file", file.Name()))
		}
	}

	// EVALUATE - Write results
	if executedCount > 0 {
		if err := os.WriteFile(outputFile, []byte(output.String()), shared.ConfigFilePerm); err != nil {
			return fmt.Errorf("failed to write custom hooks output: %w", err)
		}

		logger.Info("Custom hooks executed",
			zap.String("output_file", outputFile),
			zap.Int("hooks_executed", executedCount))
	} else {
		logger.Info("No executable hooks found")
	}

	return nil
}
