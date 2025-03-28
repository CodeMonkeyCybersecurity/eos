// cmd/disable/suspension.go

package disable

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var disableSuspensionCmd = &cobra.Command{
	Use:   "suspension",
	Short: "Disable OS-level suspension and hibernation",
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()
		log.Info("Disabling system suspension and hibernation...")

		if err := disableSystemdTargets(); err != nil {
			log.Error("Failed to disable suspend/hibernate targets", zap.Error(err))
			fmt.Println("Failed to disable system targets:", err)
			os.Exit(1)
		}

		if err := maskSleepTargets(); err != nil {
			log.Error("Failed to mask sleep targets", zap.Error(err))
			fmt.Println("Failed to mask sleep targets:", err)
			os.Exit(1)
		}

		if err := disableLogindSleep(); err != nil {
			log.Error("Failed to patch /etc/systemd/logind.conf", zap.Error(err))
			fmt.Println("Failed to modify logind.conf:", err)
			os.Exit(1)
		}

		log.Info("✅ System suspension and hibernation disabled successfully.")
		fmt.Println("✅ Suspension/hibernation is now disabled and persistent.")
	},
}

func disableSystemdTargets() error {
	targets := []string{
		"suspend.target",
		"sleep.target",
		"hibernate.target",
		"hybrid-sleep.target",
	}
	for _, t := range targets {
		cmd := exec.Command("systemctl", "mask", t)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to mask %s: %w", t, err)
		}
	}
	return nil
}

func maskSleepTargets() error {
	// You might want to ensure suspend services are masked too
	services := []string{
		"sleep.target",
		"suspend.target",
	}
	for _, s := range services {
		cmd := exec.Command("systemctl", "mask", s)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to mask %s: %w", s, err)
		}
	}
	return nil
}

func disableLogindSleep() error {
	logindPath := "/etc/systemd/logind.conf"

	patches := map[string]string{
		"HandleSuspendKey": "ignore",
		"HandleLidSwitch":  "ignore",
		"HandleLidSwitchDocked": "ignore",
	}

	data, err := os.ReadFile(logindPath)
	if err != nil {
		return fmt.Errorf("failed to read logind.conf: %w", err)
	}

	content := string(data)
	for key, val := range patches {
		content = replaceOrAppend(content, key, fmt.Sprintf("%s=%s", key, val))
	}

	if err := os.WriteFile(logindPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write logind.conf: %w", err)
	}

	// Restart systemd-logind to apply changes
	return exec.Command("systemctl", "restart", "systemd-logind").Run()
}

func replaceOrAppend(content, key, newLine string) string {
	lines := []string{}
	found := false
	for _, line := range splitLines(content) {
		if startsWithKey(line, key) {
			lines = append(lines, newLine)
			found = true
		} else {
			lines = append(lines, line)
		}
	}
	if !found {
		lines = append(lines, newLine)
	}
	return joinLines(lines)
}

func startsWithKey(line, key string) bool {
	return len(line) >= len(key) && line[:len(key)] == key
}

func splitLines(s string) []string {
	return []string{}
}

func joinLines(lines []string) string {
	return ""
}
