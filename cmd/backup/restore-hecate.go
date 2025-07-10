// cmd/backup/restore-hecate.go

package backup

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var timestampFlag string

var RestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore configuration and files from backup",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, _ *cobra.Command, _ []string) error {
		if timestampFlag != "" {
			return autoRestore(rc, timestampFlag)
		}
		return interactiveRestore(rc)
	}),
}

func init() {
	RestoreCmd.Flags().StringVarP(&timestampFlag, "timestamp", "t", "",
		"Backup timestamp (YYYYMMDD-HHMMSS). Omit for interactive mode.")
}


// TODO: HELPER_REFACTOR - Move to pkg/backup or pkg/hecate/backup
// Type: Business Logic
// Related functions: interactiveRestore, restoreResource
// Dependencies: eos_io, shared, fmt, zap
// TODO: Move to pkg/backup or pkg/hecate/backup
func autoRestore(rc *eos_io.RuntimeContext, ts string) error {
	resources := []struct{ prefix, dest string }{
		{fmt.Sprintf("%s.%s.bak", shared.DefaultConfDir, ts), shared.DefaultConfDir},
		{fmt.Sprintf("%s.%s.bak", shared.DefaultCertsDir, ts), shared.DefaultCertsDir},
		{fmt.Sprintf("%s.%s.bak", shared.DefaultComposeYML, ts), shared.DefaultComposeYML},
	}
	rc.Log.Info("Starting automatic restore", zap.String("timestamp", ts))
	for _, r := range resources {
		if err := restoreResource(rc, r.prefix, r.dest); err != nil {
			return err
		}
	}
	return nil
}

// TODO: HELPER_REFACTOR - Move to pkg/backup or pkg/hecate/backup
// Type: Business Logic
// Related functions: autoRestore, restoreResource
// Dependencies: eos_io, bufio, fmt, strings, os
// TODO: Move to pkg/backup or pkg/hecate/backup
func interactiveRestore(rc *eos_io.RuntimeContext) error {
	menu := []struct {
		label, prefix, dest string
	}{
		{"1) Configuration", shared.DefaultConfDir + ".", shared.DefaultConfDir},
		{"2) Certificates", shared.DefaultCertsDir + ".", shared.DefaultCertsDir},
		{"3) Compose file", shared.DefaultComposeYML + ".", shared.DefaultComposeYML},
		{"4) All resources", "", ""},
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Select resource to restore:")
	for _, m := range menu[:3] {
		fmt.Println(m.label)
	}
	fmt.Print("Enter choice (1-4): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1", "2", "3":
		idx := choice[0] - '1'
		return restoreResource(rc, menu[idx].prefix, menu[idx].dest)
	case "4":
		// require timestamp for “all”
		if timestampFlag == "" {
			return fmt.Errorf("must provide --timestamp to restore all")
		}
		return autoRestore(rc, timestampFlag)
	default:
		return fmt.Errorf("invalid choice %q", choice)
	}
}

// TODO: HELPER_REFACTOR - Move to pkg/backup or pkg/hecate/backup
// Type: Business Logic
// Related functions: autoRestore, interactiveRestore
// Dependencies: eos_io, eos_unix, fmt, zap
// TODO: Move to pkg/backup or pkg/hecate/backup
func restoreResource(
	rc *eos_io.RuntimeContext,
	backupPattern, destDir string,
) error {
	backup, err := eos_unix.FindLatestBackup(backupPattern)
	if err != nil {
		return fmt.Errorf("find backup for %s: %w", destDir, err)
	}
	rc.Log.Info("Restoring", zap.String("backup", backup), zap.String("to", destDir))
	if err := eos_unix.Restore(rc.Ctx, backup, destDir); err != nil {
		return fmt.Errorf("restore %s: %w", destDir, err)
	}
	rc.Log.Info("Successfully restored", zap.String("to", destDir))
	return nil
}
