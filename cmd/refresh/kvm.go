// cmd/refresh/kvm.go
package refresh

import (
	"fmt"
	"strings"
	"time"

	"os"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// rescueKvmCmd represents the 'eos rescue kvm' command.
var rescueKvmCmd = &cobra.Command{
	Use:   "kvm",
	Short: "Rescue a KVM virtual machine (shutdown & open virt-rescue shell)",
	Long: `This command shuts down the specified KVM/libvirt virtual machine if it's running, 
waits for it to stop, and then opens a virt-rescue shell so you can troubleshoot it.
Example:
  eos rescue kvm --name centos-stream9-2
`,
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Grab the flag
		vmName, _ := cmd.Flags().GetString("name")
		if vmName == "" {
			return fmt.Errorf("❌ You must provide a --name (the libvirt/KVM domain name)")
		}

		log := ctx.Log.Named("rescue-kvm")
		log.Info("🛠 Starting rescue for KVM VM", zap.String("vm", vmName))

		// Check VM status
		out, err := exec.Command("virsh", "list", "--all").Output()
		if err != nil {
			return fmt.Errorf("failed to list VMs: %w", err)
		}

		if !isVMRunning(string(out), vmName) {
			log.Info("✅ VM is already shut off", zap.String("vm", vmName))
		} else {
			// Shut it down
			log.Info("🔻 Shutting down VM...", zap.String("vm", vmName))
			cmdShutdown := exec.Command("virsh", "shutdown", vmName)
			cmdShutdown.Stdout = os.Stdout
			cmdShutdown.Stderr = os.Stderr
			if err := cmdShutdown.Run(); err != nil {
				return fmt.Errorf("failed to shutdown VM: %w", err)
			}

			// Wait for shutdown
			log.Info("⏳ Waiting for VM to shut off...")
			for {
				time.Sleep(3 * time.Second)
				out, err := exec.Command("virsh", "list", "--all").Output()
				if err != nil {
					return fmt.Errorf("failed to list VMs during shutdown wait: %w", err)
				}
				if !isVMRunning(string(out), vmName) {
					log.Info("✅ VM is now shut off", zap.String("vm", vmName))
					break
				}
				log.Debug("...still waiting for VM to shut off")
			}
		}

		// Launch virt-rescue
		log.Info("🚨 Launching virt-rescue shell (requires sudo)", zap.String("vm", vmName))
		cmdRescue := exec.Command("sudo", "virt-rescue", "-d", vmName)
		cmdRescue.Stdout = os.Stdout
		cmdRescue.Stderr = os.Stderr
		cmdRescue.Stdin = os.Stdin
		if err := cmdRescue.Run(); err != nil {
			return fmt.Errorf("virt-rescue failed: %w", err)
		}

		log.Info("✅ Rescue session completed")
		return nil
	}),
}

// isVMRunning checks if the VM appears as 'running' in virsh output.
func isVMRunning(virshList string, vmName string) bool {
	for _, line := range strings.Split(virshList, "\n") {
		if strings.Contains(line, vmName) && strings.Contains(line, "running") {
			return true
		}
	}
	return false
}

func init() {
	// Add the kvm subcommand to the parent 'refresh' command
	rescueKvmCmd.Flags().String("name", "", "Domain name of the KVM virtual machine (required)")
	_ = rescueKvmCmd.MarkFlagRequired("name")

	RefreshCmd.AddCommand(rescueKvmCmd)
}
