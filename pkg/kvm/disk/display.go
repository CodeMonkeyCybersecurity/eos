//go:build linux

// pkg/kvm/disk/display.go
// Display and user interaction functions for disk resize operations

package disk

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// DisplayAssessment shows assessment results to the user
func DisplayAssessment(ctx context.Context, a *Assessment) {
	logger := otelzap.Ctx(ctx)

	logger.Info("╔═══════════════════════════════════════════════════════════════╗")
	logger.Info("║                    ASSESSMENT RESULTS                         ║")
	logger.Info("╠═══════════════════════════════════════════════════════════════╣")
	logger.Info(fmt.Sprintf("║ VM Name: %-52s║", a.VMName))
	logger.Info(fmt.Sprintf("║ State: %-54s║", a.State))
	logger.Info(fmt.Sprintf("║ Current Size: %-47s║", FormatBytes(a.CurrentSizeBytes)))
	logger.Info(fmt.Sprintf("║ Requested Size: %-45s║", FormatBytes(a.RequestedSizeBytes)))
	logger.Info(fmt.Sprintf("║ Change: %-53s║", FormatBytes(a.ChangeBytes)))
	logger.Info(fmt.Sprintf("║ Disk Format: %-48s║", a.Format))
	logger.Info(fmt.Sprintf("║ Guest Agent: %-48s║", formatBool(a.HasGuestAgent)))
	logger.Info(fmt.Sprintf("║ Backup Available: %-43s║", formatBool(a.BackupExists)))
	if a.BackupExists {
		logger.Info(fmt.Sprintf("║ Backup Age: %-49s║", a.BackupAge.Round(time.Minute).String()))
	}
	logger.Info(fmt.Sprintf("║ Host Free Space: %-44s║", FormatBytes(a.HostFreeSpaceBytes)))
	logger.Info("╚═══════════════════════════════════════════════════════════════╝")

	// Display risks
	if len(a.Risks) > 0 {
		logger.Info("Identified Risks:")
		for _, risk := range a.Risks {
			level := strings.ToUpper(string(risk.Level))
			logger.Info(fmt.Sprintf("  [%s] %s", level, risk.Description))
			logger.Info(fmt.Sprintf("         Mitigation: %s", risk.Mitigation))
		}
	}

	// Display required actions
	if len(a.RequiredActions) > 0 {
		logger.Info("Required Actions:")
		for _, action := range a.RequiredActions {
			logger.Info(fmt.Sprintf("  • %s", action))
		}
	}
}

// DisplayPlan shows the planned operations for a resize
func DisplayPlan(ctx context.Context, a *Assessment) {
	logger := otelzap.Ctx(ctx)

	logger.Info("Planned Operations:")
	logger.Info("  1. Create safety backup")
	logger.Info(fmt.Sprintf("  2. Resize disk from %s to %s",
		FormatBytes(a.CurrentSizeBytes),
		FormatBytes(a.RequestedSizeBytes)))

	if a.State == "running" && a.HasGuestAgent {
		logger.Info("  3. Resize guest filesystem automatically")
	} else {
		logger.Info("  3. Manual guest filesystem resize required")
	}

	logger.Info("  4. Verify resize success")
}

// DisplayPostResizeInstructions shows instructions after resize
func DisplayPostResizeInstructions(ctx context.Context, a *Assessment) {
	logger := otelzap.Ctx(ctx)

	logger.Info("")
	logger.Info("POST-RESIZE INSTRUCTIONS:")
	logger.Info("The disk has been resized at the hypervisor level.")

	if a.State == "shut off" {
		logger.Info("Start the VM and perform filesystem resize inside the guest OS:")
	} else {
		logger.Info("Perform filesystem resize inside the guest OS:")
	}

	logger.Info("")
	logger.Info("For Linux guests:")
	logger.Info("  1. growpart /dev/vda 2")
	logger.Info("  2. pvresize /dev/vda2")
	logger.Info("  3. lvextend -l +100%FREE /dev/mapper/vg-root")
	logger.Info("  4. xfs_growfs / (XFS) or resize2fs /dev/mapper/vg-root (ext4)")
	logger.Info("")
	logger.Info("Verify with: df -h")
}

// ConfirmResize prompts the user for confirmation before resize
func ConfirmResize(a *Assessment) bool {
	fmt.Println("")
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    CONFIRMATION REQUIRED                       ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Printf("You are about to resize disk for VM '%s'\n", a.VMName)
	fmt.Printf("  From: %s\n", FormatBytes(a.CurrentSizeBytes))
	fmt.Printf("  To:   %s\n", FormatBytes(a.RequestedSizeBytes))
	fmt.Println("")

	if a.ChangeBytes < 0 {
		fmt.Println("  WARNING: This is a SHRINK operation which can cause DATA LOSS!")
		fmt.Println("Make sure the guest filesystem has been shrunk first!")
		fmt.Println("")
	}

	fmt.Print("Do you want to proceed? (type 'yes' to continue): ")
	var response string
	_, _ = fmt.Scanln(&response)

	return strings.ToLower(response) == "yes"
}

// CountHighRisks counts the number of high-severity risks
func CountHighRisks(risks []Risk) int {
	count := 0
	for _, r := range risks {
		if r.Level == RiskLevelHigh {
			count++
		}
	}
	return count
}

// formatBool formats boolean values for display
func formatBool(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
