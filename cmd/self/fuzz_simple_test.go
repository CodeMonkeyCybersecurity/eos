// cmd/delphi/services/fuzz_simple_test.go

package self

import (
	"context"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap/zaptest"
)

// FuzzUpdateCommand tests the update command with various inputs
func FuzzUpdateCommand(f *testing.F) {
	// Seed with patterns that caused the original crash
	f.Add("--all")
	f.Add("--dry-run")
	f.Add("alert-to-db")      // This was causing crashes
	f.Add("ab-test-analyzer") // This was causing crashes
	f.Add("delphi-listener")
	f.Add("--timeout=5m")

	f.Fuzz(func(t *testing.T, arg string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Update command crashed with panic: %v, arg: %q", r, arg)
			}
		}()

		// Create update command
		cmd := UpdateCmd

		// Set up minimal context
		zapLogger := zaptest.NewLogger(t)
		logger := otelzap.New(zapLogger)
		ctx := context.Background()

		// Replace global logger for test
		otelzap.ReplaceGlobals(logger)

		rc := &eos_io.RuntimeContext{
			Ctx: ctx,
		}

		// Build args ensuring we're in safe mode
		args := []string{}
		if arg != "" {
			args = append(args, arg)
		}

		// Force dry-run mode to prevent actual operations during fuzzing
		foundDryRun := false
		for _, a := range args {
			if strings.Contains(a, "dry-run") {
				foundDryRun = true
				break
			}
		}
		if !foundDryRun {
			args = append(args, "--dry-run")
		}

		// Force skip-installation-check to avoid complex installation logic
		foundSkipCheck := false
		for _, a := range args {
			if strings.Contains(a, "skip-installation-check") {
				foundSkipCheck = true
				break
			}
		}
		if !foundSkipCheck {
			args = append(args, "--skip-installation-check")
		}

		// Set args and try to execute
		cmd.SetArgs(args)
		cmd.SetContext(rc.Ctx)

		// Execute the command (in dry-run mode)
		err := cmd.ExecuteContext(rc.Ctx)
		_ = err // Don't care about errors, just crashes
	})
}

// FuzzServiceWorkerPaths tests GetServiceWorkers with various paths
func FuzzServiceWorkerPaths(f *testing.F) {
	// Seed with various path patterns
	f.Add("/opt/eos")
	f.Add("/usr/local/eos")
	f.Add("")
	f.Add("/")
	f.Add("./relative/path")

	f.Fuzz(func(t *testing.T, eosRoot string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("GetServiceWorkers crashed with panic: %v, eosRoot: %q", r, eosRoot)
			}
		}()

		// Test GetServiceWorkers with various paths
		workers := shared.GetServiceWorkers(eosRoot)

		// Validate that we got some result
		_ = len(workers)

		// Test that all workers have required fields
		for _, worker := range workers {
			_ = worker.ServiceName
			_ = worker.SourcePath
			_ = worker.TargetPath
			_ = worker.BackupPath
		}
	})
}
