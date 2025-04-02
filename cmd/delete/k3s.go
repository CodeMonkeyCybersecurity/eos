// cmd/delete/k3s.go
package delete

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var DeleteK3sCmd = &cobra.Command{
	Use:   "k3s",
	Short: "Uninstall K3s from this machine",
	Long: `Detects whether this machine is running a K3s server or agent,
and removes it by running the appropriate uninstall scripts in the correct order.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := uninstallK3s(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to uninstall K3s: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ K3s uninstallation completed.")
	},
}

func uninstallK3s() error {
	scripts := map[string]string{
		"server": "/usr/local/bin/k3s-uninstall.sh",
		"agent":  "/usr/local/bin/k3s-agent-uninstall.sh",
		"kill":   "/usr/local/bin/k3s-killall.sh",
	}

	var ranAny bool
	for role, path := range scripts {
		if fileExists(path) {
			fmt.Printf("▶ Detected %s uninstall script: %s\n", role, path)
			err := runScript(path)
			if err != nil {
				return fmt.Errorf("failed to run %s script: %w", role, err)
			}
			ranAny = true
		}
	}

	if !ranAny {
		return fmt.Errorf("no uninstall scripts found at expected paths")
	}

	return nil
}

func runScript(path string) error {
	cmd := exec.Command("sudo", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	fmt.Printf("➡ Running %s...\n", filepath.Base(path))
	return cmd.Run()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func init() {

	// Initialize the shared logger for the entire install package
	DeleteCmd.AddCommand(DeleteK3sCmd)

}
