// pkg/backup/restore_hecate.go
package backup

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RestoreResource restores a single resource from backup
// PATTERN: Assess → Intervene → Evaluate
func RestoreResource(
	rc *eos_io.RuntimeContext,
	backupPattern, destDir string,
) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Find backup file
	logger.Info("Assessing backup availability",
		zap.String("pattern", backupPattern),
		zap.String("destination", destDir))

	backup, err := eos_unix.FindLatestBackup(backupPattern)
	if err != nil {
		logger.Error("Failed to find backup",
			zap.String("pattern", backupPattern),
			zap.String("destination", destDir),
			zap.Error(err))
		return fmt.Errorf("find backup for %s: %w", destDir, err)
	}

	logger.Info("Found backup to restore",
		zap.String("backup_path", backup),
		zap.String("destination", destDir))

	// INTERVENE - Perform restore
	logger.Info("Restoring resource",
		zap.String("backup", backup),
		zap.String("to", destDir))

	if err := eos_unix.Restore(rc.Ctx, backup, destDir); err != nil {
		logger.Error("Restore failed",
			zap.String("backup", backup),
			zap.String("destination", destDir),
			zap.Error(err))
		return fmt.Errorf("restore %s: %w", destDir, err)
	}

	// EVALUATE - Confirm success
	logger.Info("Successfully restored resource",
		zap.String("backup", backup),
		zap.String("destination", destDir))

	return nil
}

// AutoRestore performs automatic restore of all Hecate resources for a given timestamp
// PATTERN: Assess → Intervene → Evaluate
func AutoRestore(rc *eos_io.RuntimeContext, timestamp string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Define resources to restore
	resources := []struct {
		name   string
		prefix string
		dest   string
	}{
		{
			name:   "configuration",
			prefix: fmt.Sprintf("%s.%s.bak", shared.DefaultConfDir, timestamp),
			dest:   shared.DefaultConfDir,
		},
		{
			name:   "certificates",
			prefix: fmt.Sprintf("%s.%s.bak", shared.DefaultCertsDir, timestamp),
			dest:   shared.DefaultCertsDir,
		},
		{
			name:   "compose_file",
			prefix: fmt.Sprintf("%s.%s.bak", shared.DefaultComposeYML, timestamp),
			dest:   shared.DefaultComposeYML,
		},
	}

	logger.Info("Starting automatic restore",
		zap.String("timestamp", timestamp),
		zap.Int("resource_count", len(resources)))

	// INTERVENE - Restore each resource
	for i, r := range resources {
		logger.Info("Restoring resource",
			zap.Int("step", i+1),
			zap.Int("total", len(resources)),
			zap.String("resource", r.name),
			zap.String("destination", r.dest))

		if err := RestoreResource(rc, r.prefix, r.dest); err != nil {
			logger.Error("Failed to restore resource",
				zap.String("resource", r.name),
				zap.Error(err))
			return err
		}

		logger.Info("Resource restored successfully",
			zap.String("resource", r.name))
	}

	// EVALUATE - All resources restored
	logger.Info("Automatic restore completed successfully",
		zap.String("timestamp", timestamp),
		zap.Int("resources_restored", len(resources)))

	return nil
}

// InteractiveRestore provides an interactive menu for selecting resources to restore
// PATTERN: Assess → Intervene → Evaluate
func InteractiveRestore(rc *eos_io.RuntimeContext, timestamp string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Define menu options
	menu := []struct {
		label  string
		name   string
		prefix string
		dest   string
	}{
		{
			label:  "1) Configuration",
			name:   "configuration",
			prefix: shared.DefaultConfDir + ".",
			dest:   shared.DefaultConfDir,
		},
		{
			label:  "2) Certificates",
			name:   "certificates",
			prefix: shared.DefaultCertsDir + ".",
			dest:   shared.DefaultCertsDir,
		},
		{
			label:  "3) Compose file",
			name:   "compose_file",
			prefix: shared.DefaultComposeYML + ".",
			dest:   shared.DefaultComposeYML,
		},
		{
			label:  "4) All resources",
			name:   "all",
			prefix: "",
			dest:   "",
		},
	}

	logger.Info("Entering interactive restore mode")

	// Display menu
	reader := bufio.NewReader(os.Stdin)
	logger.Info("terminal prompt: Select resource to restore:")
	for _, m := range menu {
		logger.Info("terminal prompt:", zap.String("option", m.label))
	}
	logger.Info("terminal prompt: Enter choice (1-4): ")

	// Read user choice
	choice, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read user input: %w", err)
	}
	choice = strings.TrimSpace(choice)

	logger.Info("User selected option",
		zap.String("choice", choice))

	// INTERVENE - Process user choice
	switch choice {
	case "1", "2", "3":
		idx := choice[0] - '1'
		selectedResource := menu[idx]

		logger.Info("Restoring single resource",
			zap.String("resource", selectedResource.name))

		return RestoreResource(rc, selectedResource.prefix, selectedResource.dest)

	case "4":
		// Require timestamp for "all" option
		if timestamp == "" {
			logger.Error("Timestamp required for restoring all resources")
			return fmt.Errorf("must provide timestamp to restore all resources")
		}

		logger.Info("Restoring all resources")
		return AutoRestore(rc, timestamp)

	default:
		logger.Error("Invalid menu choice",
			zap.String("choice", choice))
		return fmt.Errorf("invalid choice %q", choice)
	}
}
