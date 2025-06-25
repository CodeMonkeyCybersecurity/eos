// cmd/update/hostname.go
package update

import (
	"os"
	"os/exec"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var UpdateHostnameCmd = &cobra.Command{
	Use:   "hostname",
	Short: "Update the system hostname",
	Long:  `Update the system hostname by modifying /etc/hostname and /etc/hosts.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return UpdateHostname(rc)
	}),
}

// UpdateHostname updates the system hostname
func UpdateHostname(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Starting hostname update",
		zap.String("user", os.Getenv("USER")),
		zap.String("function", "UpdateHostname"))

	// Get the current hostname
	currentHostname, err := os.Hostname()
	if err != nil {
		logger.Error(" Failed to retrieve current hostname",
			zap.Error(err),
			zap.String("troubleshooting", "Check system configuration"))
		return err
	}
	logger.Info(" Current hostname retrieved",
		zap.String("hostname", currentHostname))

	// Ask for confirmation to proceed using default No
	if !interaction.PromptYesNo(rc.Ctx, "Do you want to change the hostname?", false) {
		logger.Info(" Hostname change aborted by user")
		return nil
	}

	// Ask for the new hostname
	newHostname := interaction.PromptInput(rc.Ctx, "Enter the new hostname", "")
	newHostname = strings.TrimSpace(newHostname)

	// Check if the input is not empty
	if newHostname == "" {
		logger.Error(" Empty hostname provided",
			zap.String("troubleshooting", "Hostname cannot be empty"))
		return nil
	}

	logger.Info(" Changing hostname",
		zap.String("old_hostname", currentHostname),
		zap.String("new_hostname", newHostname))

	// Change the hostname temporarily
	logger.Info(" Executing command",
		zap.String("command", "hostname"),
		zap.Strings("args", []string{newHostname}))
	err = exec.Command("hostname", newHostname).Run()
	if err != nil {
		logger.Error(" Failed to change hostname temporarily",
			zap.Error(err),
			zap.String("command", "hostname"),
			zap.String("new_hostname", newHostname),
			zap.String("troubleshooting", "Check permissions and system state"))
		return err
	}
	logger.Info(" Temporary hostname change completed")

	// Change the hostname permanently
	logger.Info(" Writing new hostname to /etc/hostname",
		zap.String("file_path", "/etc/hostname"),
		zap.String("new_hostname", newHostname))
	err = os.WriteFile("/etc/hostname", []byte(newHostname+"\n"), 0644)
	if err != nil {
		logger.Error(" Failed to write /etc/hostname",
			zap.Error(err),
			zap.String("file_path", "/etc/hostname"),
			zap.String("troubleshooting", "Check permissions for /etc/hostname"))
		return err
	}
	logger.Info(" Permanent hostname file updated")

	// Update the /etc/hosts file
	logger.Info(" Executing command",
		zap.String("command", "sed"),
		zap.Strings("args", []string{"-i", "s/" + currentHostname + "/" + newHostname + "/g", "/etc/hosts"}))
	err = exec.Command("sed", "-i", "s/"+currentHostname+"/"+newHostname+"/g", "/etc/hosts").Run()
	if err != nil {
		logger.Error(" Failed to update /etc/hosts",
			zap.Error(err),
			zap.String("file_path", "/etc/hosts"),
			zap.String("old_hostname", currentHostname),
			zap.String("new_hostname", newHostname),
			zap.String("troubleshooting", "Check permissions for /etc/hosts"))
		return err
	}
	logger.Info(" /etc/hosts file updated")

	logger.Info(" Hostname change complete",
		zap.String("old_hostname", currentHostname),
		zap.String("new_hostname", newHostname))
	return nil
}

// init registers subcommands for the update command
func init() {
	UpdateCmd.AddCommand(UpdateHostnameCmd)
}
