package restore

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
)

func main() {
	// Restore conf.d directory.
	info, err := os.Stat(hecate.BackupConf)
	if err != nil || !info.IsDir() {
		fmt.Printf("Error: Backup directory '%s' does not exist.\n", hecate.BackupConf)
		os.Exit(1)
	}
	if err := system.Rm(hecate.DstConf, "destination conf", log); err != nil {
		fmt.Printf("Error removing directory '%s': %v\n", hecate.DstConf, err)
		os.Exit(1)
	}
	if err := system.CopyDir(hecate.BackupConf, hecate.DstConf, log); err != nil {
		fmt.Printf("Error during restore of %s: %v\n", hecate.BackupConf, err)
		os.Exit(1)
	}
	fmt.Printf("Restore complete: '%s' has been restored to '%s'.\n", hecate.BackupConf, hecate.DstConf)

	// Restore certs directory.
	info, err = os.Stat(hecate.BackupCerts)
	if err != nil || !info.IsDir() {
		fmt.Printf("Error: Backup directory '%s' does not exist.\n", hecate.BackupCerts)
		os.Exit(1)
	}
	if err := system.Rm(hecate.DstCerts, "destination certs", log); err != nil {
		fmt.Printf("Error removing directory '%s': %v\n", hecate.DstCerts, err)
		os.Exit(1)
	}
	if err := system.CopyDir(hecate.BackupCerts, hecate.DstCerts, log); err != nil {
		fmt.Printf("Error during restore of %s: %v\n", hecate.BackupCerts, err)
		os.Exit(1)
	}
	fmt.Printf("Restore complete: '%s' has been restored to '%s'.\n", hecate.BackupCerts, hecate.DstCerts)

	// Restore docker-compose.yml file.
	info, err = os.Stat(hecate.BackupCompose)
	if err != nil || info.IsDir() {
		fmt.Printf("Error: Backup file '%s' does not exist.\n", hecate.BackupCompose)
		os.Exit(1)
	}
	if err := system.Rm(hecate.DstCompose, "destination compose file", log); err != nil {
		fmt.Printf("Error removing file '%s': %v\n", hecate.DstCompose, err)
		os.Exit(1)
	}
	if err := system.CopyFile(hecate.BackupCompose, hecate.DstCompose, log); err != nil {
		fmt.Printf("Error during restore of %s: %v\n", hecate.BackupCompose, err)
		os.Exit(1)
	}
	fmt.Printf("Restore complete: '%s' has been restored to '%s'.\n", hecate.BackupCompose, hecate.DstCompose)
}
