// cmd/disable/suspension.go

package disable

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var disableSuspensionCmd = &cobra.Command{
	Use:   "suspension",
	Short: "Disable OS-level suspension and hibernation",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		otelzap.Ctx(rc.Ctx).Info("Disabling system suspension and hibernation...")

		if runtime.GOOS != "linux" {
			otelzap.Ctx(rc.Ctx).Warn("System suspension disabling is only supported on Linux.")
			fmt.Println(" This command is not supported on your operating eos_unix.")
			return nil
		}

		if err := disableSystemdTargets(); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to disable suspend/hibernate targets", zap.Error(err))
			return fmt.Errorf("failed to disable system targets: %w", err)
		}

		if err := maskSleepTargets(); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to mask sleep targets", zap.Error(err))
			return fmt.Errorf("failed to mask sleep targets: %w", err)
		}

		if err := disableLogindSleep(rc); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to patch /etc/systemd/logind.conf", zap.Error(err))
			return fmt.Errorf("failed to modify logind.conf: %w", err)
		}

		otelzap.Ctx(rc.Ctx).Info(" System suspension and hibernation disabled successfully.")
		fmt.Println(" Suspension/hibernation is now disabled and persistent.")
		return nil
	}),
}

func init() {
	DisableCmd.AddCommand(disableSuspensionCmd)
}

// disableSystemdTargets disables suspend and hibernate targets
func disableSystemdTargets() error {
	fmt.Println(" Disabling suspend.target and hibernate.target...")
	cmd := exec.Command("systemctl", "disable", "suspend.target", "hibernate.target")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// maskSleepTargets masks system sleep targets
func maskSleepTargets() error {
	fmt.Println(" Masking sleep.target, suspend.target, hibernate.target...")
	cmd := exec.Command("systemctl", "mask", "sleep.target", "suspend.target", "hibernate.target")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func disableLogindSleep(rc *eos_io.RuntimeContext) error {
	const configPath = "/etc/systemd/logind.conf"
	fmt.Println(" Patching", configPath, "to disable sleep options...")

	input, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("could not read %s: %w", configPath, err)
	}

	var output bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(input))
	settings := map[string]string{
		"HandleSuspendKey":   "ignore",
		"HandleHibernateKey": "ignore",
		"HandleLidSwitch":    "ignore",
	}

	seen := map[string]bool{}
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		for key := range settings {
			if strings.HasPrefix(trimmed, key+"=") {
				output.WriteString(fmt.Sprintf("%s=%s\n", key, settings[key]))
				seen[key] = true
				goto next
			}
		}

		output.WriteString(line + "\n")
	next:
	}

	for key, value := range settings {
		if !seen[key] {
			output.WriteString(fmt.Sprintf("%s=%s\n", key, value))
		}
	}

	if err := os.WriteFile(configPath, output.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write updated config: %w", err)
	}

	fmt.Println(" Reloading systemd daemon and restarting systemd-logind...")

	// Reload systemd to apply changes
	if err := exec.Command("systemctl", "daemon-reexec").Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Restart logind to pick up the config changes
	if err := exec.Command("systemctl", "restart", "systemd-logind").Run(); err != nil {
		return fmt.Errorf("failed to restart systemd-logind: %w", err)
	}

	//  Logging fix
	otelzap.Ctx(rc.Ctx).Info("Suspension hardening complete", zap.Strings("modified_units", []string{
		"suspend.target", "hibernate.target", "sleep.target", "systemd-logind",
	}))

	return nil
}
