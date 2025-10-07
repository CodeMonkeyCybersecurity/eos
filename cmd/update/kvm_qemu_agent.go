package update

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"libvirt.org/go/libvirt"
)

var (
	qemuAgentAll        bool
	qemuAgentDryRun     bool
	qemuAgentForce      bool
	qemuAgentBatchSize  int
	qemuAgentWaitSecond int
	qemuAgentNoBackup   bool
	qemuAgentNoRestart  bool
)

// UpdateKVMQEMUAgentCmd adds QEMU guest agent to existing KVM VMs
var UpdateKVMQEMUAgentCmd = &cobra.Command{
	Use:   "kvm-qemu-agent [vm-name...]",
	Short: "Add QEMU guest agent channel to existing KVM virtual machines",
	Long: `Add QEMU guest agent virtio-serial channel to existing KVM VMs.

This command safely modifies VM XML configurations to add the guest agent channel.
The guest agent must still be installed inside the VM guest OS for full functionality.

SAFETY FEATURES:
- Automatic XML backup before modifications
- Checks if guest agent channel already exists
- Progressive rollout for --all operations
- Dry-run mode to preview changes
- Automatic rollback on failure
- Health verification after changes

WHAT THIS COMMAND DOES:
1. Adds virtio-serial controller (if missing)
2. Adds org.qemu.guest_agent.0 channel
3. Backs up original XML configuration
4. Verifies changes were applied correctly

WHAT YOU STILL NEED TO DO:
Inside each VM guest OS, install and enable the guest agent:
  Ubuntu/Debian: apt-get install qemu-guest-agent && systemctl enable --now qemu-guest-agent
  RHEL/Rocky:    dnf install qemu-guest-agent && systemctl enable --now qemu-guest-agent

EXAMPLES:
  # Add to a single VM
  eos update kvm-qemu-agent centos-stream9

  # Preview changes without modifying
  eos update kvm-qemu-agent centos-stream9 --dry-run

  # Add to all VMs (progressive rollout)
  eos update kvm-qemu-agent --all

  # Add to all VMs with larger batches
  eos update kvm-qemu-agent --all --batch-size 5 --wait-between 15

  # Add to multiple specific VMs
  eos update kvm-qemu-agent vm1 vm2 vm3

NOTE: Running VMs will require a restart for changes to take effect.
      Use --no-restart to skip automatic restart prompts.`,
	RunE: eos_cli.Wrap(runUpdateKVMQEMUAgent),
}

func init() {
	UpdateKVMQEMUAgentCmd.Flags().BoolVar(&qemuAgentAll, "all", false, "Add guest agent to all VMs")
	UpdateKVMQEMUAgentCmd.Flags().BoolVar(&qemuAgentDryRun, "dry-run", false, "Preview changes without applying")
	UpdateKVMQEMUAgentCmd.Flags().BoolVar(&qemuAgentForce, "force", false, "Skip confirmation prompts")
	UpdateKVMQEMUAgentCmd.Flags().IntVar(&qemuAgentBatchSize, "batch-size", 3, "Number of VMs to update in each batch")
	UpdateKVMQEMUAgentCmd.Flags().IntVar(&qemuAgentWaitSecond, "wait-between", 30, "Seconds to wait between batches")
	UpdateKVMQEMUAgentCmd.Flags().BoolVar(&qemuAgentNoBackup, "no-backup", false, "Skip XML backup (not recommended)")
	UpdateKVMQEMUAgentCmd.Flags().BoolVar(&qemuAgentNoRestart, "no-restart", false, "Skip restart prompts for running VMs")

	UpdateCmd.AddCommand(UpdateKVMQEMUAgentCmd)
}

func runUpdateKVMQEMUAgent(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) (err error) {
	logger := otelzap.Ctx(rc.Ctx)
	defer rc.End(&err)

	logger.Info("Starting QEMU guest agent update operation")

	// ASSESS - Determine target VMs
	var targetVMs []string

	if qemuAgentAll {
		logger.Info("Phase 1: ASSESS - Scanning all VMs")
		allVMs, err := listAllVMs(rc.Ctx)
		if err != nil {
			return fmt.Errorf("failed to list VMs: %w", err)
		}

		if len(allVMs) == 0 {
			logger.Info("No VMs found on this system")
			return nil
		}

		targetVMs = allVMs
		logger.Info("Found VMs to process", zap.Int("count", len(targetVMs)))
	} else {
		if len(args) == 0 {
			return fmt.Errorf("no VMs specified (use --all to update all VMs or provide VM names)")
		}
		targetVMs = args
		logger.Info("Updating specific VMs", zap.Strings("vms", targetVMs))
	}

	// Check which VMs actually need updates
	vmsNeedingUpdate, vmsWithAgent, err := assessVMs(rc.Ctx, targetVMs)
	if err != nil {
		return fmt.Errorf("failed to assess VMs: %w", err)
	}

	if len(vmsWithAgent) > 0 {
		logger.Info("VMs already have guest agent channel", zap.Strings("vms", vmsWithAgent))
	}

	if len(vmsNeedingUpdate) == 0 {
		logger.Info("All specified VMs already have guest agent channel configured")
		return nil
	}

	logger.Info("VMs needing guest agent update",
		zap.Int("total", len(targetVMs)),
		zap.Int("needs_update", len(vmsNeedingUpdate)),
		zap.Int("already_configured", len(vmsWithAgent)))

	// Show impact and get confirmation (unless --force)
	if !qemuAgentForce && !qemuAgentDryRun {
		if !showImpactAndConfirm(rc, vmsNeedingUpdate) {
			logger.Info("Operation cancelled by user")
			return nil
		}
	}

	// Dry run mode - show what would be done
	if qemuAgentDryRun {
		logger.Info("DRY RUN MODE - No changes will be made")
		for _, vmName := range vmsNeedingUpdate {
			logger.Info("Would add guest agent channel", zap.String("vm", vmName))
		}
		logger.Info("Dry run complete - no changes applied")
		return nil
	}

	// INTERVENE - Apply updates with progressive rollout
	logger.Info("Phase 2: INTERVENE - Applying guest agent updates")

	if len(vmsNeedingUpdate) == 1 {
		// Single VM - direct update
		return updateSingleVM(rc, vmsNeedingUpdate[0])
	}

	// Multiple VMs - use progressive rollout
	return updateMultipleVMs(rc, vmsNeedingUpdate)
}

func listAllVMs(ctx context.Context) ([]string, error) {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer conn.Close()

	domains, err := conn.ListAllDomains(0)
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	var vmNames []string
	for _, domain := range domains {
		name, err := domain.GetName()
		if err != nil {
			continue
		}
		vmNames = append(vmNames, name)
		domain.Free()
	}

	return vmNames, nil
}

func assessVMs(ctx context.Context, vmNames []string) (needsUpdate, hasAgent []string, err error) {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer conn.Close()

	for _, vmName := range vmNames {
		domain, err := conn.LookupDomainByName(vmName)
		if err != nil {
			// VM doesn't exist - skip
			continue
		}

		xmlDesc, err := domain.GetXMLDesc(0)
		domain.Free()

		if err != nil {
			return nil, nil, fmt.Errorf("failed to get XML for %s: %w", vmName, err)
		}

		// Check if guest agent channel already exists
		if strings.Contains(xmlDesc, "org.qemu.guest_agent.0") {
			hasAgent = append(hasAgent, vmName)
		} else {
			needsUpdate = append(needsUpdate, vmName)
		}
	}

	return needsUpdate, hasAgent, nil
}

func showImpactAndConfirm(rc *eos_io.RuntimeContext, vmsNeedingUpdate []string) bool {
	logger := otelzap.Ctx(rc.Ctx)

	// Count running VMs
	runningCount := 0
	for _, vmName := range vmsNeedingUpdate {
		if isVMRunning(rc.Ctx, vmName) {
			runningCount++
		}
	}

	logger.Info("╔═══════════════════════════════════════════════════════════════╗")
	logger.Info("║                    MASS OPERATION SUMMARY                     ║")
	logger.Info("╠═══════════════════════════════════════════════════════════════╣")
	logger.Info(fmt.Sprintf("║ Operation: Add QEMU Guest Agent Channel                       ║"))
	logger.Info(fmt.Sprintf("║ Total VMs to update: %-41d║", len(vmsNeedingUpdate)))
	logger.Info(fmt.Sprintf("║ Running VMs (may need restart): %-26d║", runningCount))
	logger.Info(fmt.Sprintf("║ Batch size: %-50d║", qemuAgentBatchSize))
	logger.Info(fmt.Sprintf("║ Wait between batches: %-39ds║", qemuAgentWaitSecond))
	logger.Info("╚═══════════════════════════════════════════════════════════════╝")
	logger.Info("")
	logger.Info("This operation will:")
	logger.Info("  ✓ Modify VM XML configurations")
	logger.Info("  ✓ Add virtio-serial controller (if missing)")
	logger.Info("  ✓ Add guest agent channel device")
	logger.Info("  ✓ Create backups before modification")
	logger.Info("")
	logger.Info("Running VMs will require restart for changes to take effect")
	logger.Info("The guest agent software must still be installed inside each VM")
	logger.Info("")
	logger.Info("terminal prompt: Type 'yes' to continue")

	var response string
	fmt.Print("Do you want to proceed? (yes/no): ")
	fmt.Scanln(&response)

	return strings.ToLower(response) == "yes"
}

func isVMRunning(ctx context.Context, vmName string) bool {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return false
	}
	defer conn.Close()

	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return false
	}
	defer domain.Free()

	state, _, err := domain.GetState()
	if err != nil {
		return false
	}

	return state == libvirt.DOMAIN_RUNNING
}

func updateSingleVM(rc *eos_io.RuntimeContext, vmName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Updating single VM", zap.String("vm", vmName))

	// ASSESS - Check current state
	wasRunning := isVMRunning(rc.Ctx, vmName)
	if wasRunning {
		logger.Info("VM is currently running", zap.String("vm", vmName))
	}

	// INTERVENE - Apply update
	backupPath, err := addGuestAgentToVM(rc, vmName)
	if err != nil {
		return fmt.Errorf("failed to add guest agent to %s: %w", vmName, err)
	}

	logger.Info("Guest agent channel added successfully",
		zap.String("vm", vmName),
		zap.String("backup", backupPath))

	// EVALUATE - Verify changes
	if err := verifyGuestAgentChannel(rc.Ctx, vmName); err != nil {
		logger.Error("Verification failed - rolling back", zap.Error(err))
		if restoreErr := restoreVMXML(rc, vmName, backupPath); restoreErr != nil {
			return fmt.Errorf("verification failed and rollback failed: %w, original error: %w", restoreErr, err)
		}
		return fmt.Errorf("verification failed, rolled back: %w", err)
	}

	// Prompt for restart if VM is running
	if wasRunning && !qemuAgentNoRestart {
		logger.Info("")
		logger.Info("VM is running - restart required for guest agent channel to be available")
		logger.Info("terminal prompt: Restart VM now?")
		var response string
		fmt.Printf("Restart %s now? (yes/no): ", vmName)
		fmt.Scanln(&response)

		if strings.ToLower(response) == "yes" {
			logger.Info("Restarting VM", zap.String("vm", vmName))
			if err := kvm.RestartVM(rc.Ctx, vmName, kvm.DefaultRestartConfig()); err != nil {
				logger.Warn("Failed to restart VM - you can restart manually later", zap.Error(err))
			} else {
				logger.Info("VM restarted successfully", zap.String("vm", vmName))
			}
		} else {
			logger.Info("Skipped restart - remember to restart VM later for changes to take effect")
		}
	}

	logger.Info("Update complete", zap.String("vm", vmName))
	return nil
}

func updateMultipleVMs(rc *eos_io.RuntimeContext, vmNames []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Group VMs into batches
	batches := makeBatches(vmNames, qemuAgentBatchSize)
	logger.Info("Progressive rollout plan",
		zap.Int("total_vms", len(vmNames)),
		zap.Int("batches", len(batches)),
		zap.Int("batch_size", qemuAgentBatchSize))

	successCount := 0
	failedVMs := []string{}

	for batchNum, batch := range batches {
		logger.Info(fmt.Sprintf("Processing batch %d/%d", batchNum+1, len(batches)),
			zap.Int("vms_in_batch", len(batch)))

		for _, vmName := range batch {
			logger.Info("Updating VM", zap.String("vm", vmName))

			backupPath, err := addGuestAgentToVM(rc, vmName)
			if err != nil {
				logger.Error("Failed to add guest agent", zap.String("vm", vmName), zap.Error(err))
				failedVMs = append(failedVMs, vmName)
				continue
			}

			// Verify changes
			if err := verifyGuestAgentChannel(rc.Ctx, vmName); err != nil {
				logger.Error("Verification failed - rolling back",
					zap.String("vm", vmName), zap.Error(err))

				if restoreErr := restoreVMXML(rc, vmName, backupPath); restoreErr != nil {
					logger.Error("Rollback also failed", zap.String("vm", vmName), zap.Error(restoreErr))
				} else {
					logger.Info("Rolled back successfully", zap.String("vm", vmName))
				}

				failedVMs = append(failedVMs, vmName)
				continue
			}

			successCount++
			logger.Info("Successfully updated", zap.String("vm", vmName))
		}

		// Wait between batches (except after last batch)
		if batchNum < len(batches)-1 {
			logger.Info(fmt.Sprintf("Waiting %d seconds before next batch...", qemuAgentWaitSecond))
			time.Sleep(time.Duration(qemuAgentWaitSecond) * time.Second)
		}
	}

	// Summary
	logger.Info("Mass update complete",
		zap.Int("successful", successCount),
		zap.Int("failed", len(failedVMs)),
		zap.Int("total", len(vmNames)))

	if len(failedVMs) > 0 {
		logger.Warn("Some VMs failed to update", zap.Strings("failed_vms", failedVMs))
		return fmt.Errorf("%d VMs failed to update: %v", len(failedVMs), failedVMs)
	}

	// Note about restarts
	logger.Info("")
	logger.Info("Guest agent channels have been added to all VMs")
	logger.Info("Running VMs will need to be restarted for changes to take effect")
	logger.Info("You can restart VMs with: eos update kvm-restart <vm-name>")

	return nil
}

func makeBatches(items []string, batchSize int) [][]string {
	var batches [][]string
	for i := 0; i < len(items); i += batchSize {
		end := i + batchSize
		if end > len(items) {
			end = len(items)
		}
		batches = append(batches, items[i:end])
	}
	return batches
}

func addGuestAgentToVM(rc *eos_io.RuntimeContext, vmName string) (backupPath string, err error) {
	logger := otelzap.Ctx(rc.Ctx)

	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return "", fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer conn.Close()

	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return "", fmt.Errorf("failed to lookup domain: %w", err)
	}
	defer domain.Free()

	// Get current XML
	xmlDesc, err := domain.GetXMLDesc(0)
	if err != nil {
		return "", fmt.Errorf("failed to get XML: %w", err)
	}

	// Create backup
	if !qemuAgentNoBackup {
		backupPath, err = backupVMXML(rc, vmName, xmlDesc)
		if err != nil {
			return "", fmt.Errorf("failed to create backup: %w", err)
		}
		logger.Debug("Created XML backup", zap.String("backup", backupPath))
	}

	// Check if virtio-serial controller exists
	hasController := strings.Contains(xmlDesc, `type='virtio-serial'`) ||
		strings.Contains(xmlDesc, `type="virtio-serial"`)

	// Add virtio-serial controller if missing
	if !hasController {
		logger.Debug("Adding virtio-serial controller", zap.String("vm", vmName))

		controllerXML := `<controller type='virtio-serial' index='0'>
  <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
</controller>`

		// Attach controller (persistent configuration)
		// Use 1 for DOMAIN_AFFECT_CONFIG
		if err := domain.AttachDeviceFlags(controllerXML, 1); err != nil {
			return backupPath, fmt.Errorf("failed to add virtio-serial controller: %w", err)
		}

		logger.Debug("Virtio-serial controller added", zap.String("vm", vmName))
	}

	// Add guest agent channel
	logger.Debug("Adding guest agent channel", zap.String("vm", vmName))

	channelXML := `<channel type='unix'>
  <source mode='bind'/>
  <target type='virtio' name='org.qemu.guest_agent.0'/>
  <address type='virtio-serial' controller='0' bus='0' port='1'/>
</channel>`

	// Attach channel (persistent configuration)
	// Use 1 for DOMAIN_AFFECT_CONFIG
	if err := domain.AttachDeviceFlags(channelXML, 1); err != nil {
		return backupPath, fmt.Errorf("failed to add guest agent channel: %w", err)
	}

	logger.Debug("Guest agent channel added", zap.String("vm", vmName))

	return backupPath, nil
}

func backupVMXML(rc *eos_io.RuntimeContext, vmName, xmlContent string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	backupDir := "/var/lib/eos/backups/kvm"
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s/%s-qemu-agent-%s.xml", backupDir, vmName, timestamp)

	if err := os.WriteFile(backupPath, []byte(xmlContent), 0600); err != nil {
		return "", fmt.Errorf("failed to write backup: %w", err)
	}

	logger.Debug("VM XML backed up", zap.String("path", backupPath))
	return backupPath, nil
}

func restoreVMXML(rc *eos_io.RuntimeContext, vmName, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Restoring VM XML from backup",
		zap.String("vm", vmName),
		zap.String("backup", backupPath))

	// Read backup
	xmlBytes, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer conn.Close()

	// Undefine current VM
	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return fmt.Errorf("failed to lookup domain: %w", err)
	}

	if err := domain.Undefine(); err != nil {
		domain.Free()
		return fmt.Errorf("failed to undefine domain: %w", err)
	}
	domain.Free()

	// Redefine with backup XML
	_, err = conn.DomainDefineXML(string(xmlBytes))
	if err != nil {
		return fmt.Errorf("failed to redefine domain: %w", err)
	}

	logger.Info("VM XML restored from backup", zap.String("vm", vmName))
	return nil
}

func verifyGuestAgentChannel(ctx context.Context, vmName string) error {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer conn.Close()

	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return fmt.Errorf("failed to lookup domain: %w", err)
	}
	defer domain.Free()

	// Get updated XML
	xmlDesc, err := domain.GetXMLDesc(0)
	if err != nil {
		return fmt.Errorf("failed to get XML: %w", err)
	}

	// Verify guest agent channel exists
	if !strings.Contains(xmlDesc, "org.qemu.guest_agent.0") {
		return fmt.Errorf("guest agent channel not found in XML after update")
	}

	// Verify virtio-serial controller exists
	if !strings.Contains(xmlDesc, `type='virtio-serial'`) &&
		!strings.Contains(xmlDesc, `type="virtio-serial"`) {
		return fmt.Errorf("virtio-serial controller not found in XML after update")
	}

	return nil
}
