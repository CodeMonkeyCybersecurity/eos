package emergency

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// FlushDataSafety ensures data is flushed to disk
// Migrated from cmd/ragequit/ragequit.go flushDataSafety
func FlushDataSafety(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check what needs to be flushed
	logger.Info("Assessing data flush requirements")

	// INTERVENE - Flush various caches and buffers
	logger.Info("Flushing system caches and buffers")

	// Sync filesystem buffers
	logger.Debug("Syncing filesystem buffers")
	if err := exec.Command("sync").Run(); err != nil {
		logger.Warn("Failed to sync filesystem", zap.Error(err))
	}

	// Drop caches
	logger.Debug("Dropping system caches")
	if system.FileExists("/proc/sys/vm/drop_caches") {
		if err := os.WriteFile("/proc/sys/vm/drop_caches", []byte("3\n"), 0644); err != nil {
			logger.Warn("Failed to drop caches", zap.Error(err))
		}
	}

	// Flush database buffers if applicable
	if system.CommandExists("mysql") {
		logger.Debug("Flushing MySQL tables")
		system.RunCommandWithTimeout("mysql", []string{"-e", "FLUSH TABLES;"}, 5*time.Second)
	}

	if system.CommandExists("psql") {
		logger.Debug("Checkpointing PostgreSQL")
		system.RunCommandWithTimeout("psql", []string{"-U", "postgres", "-c", "CHECKPOINT;"}, 5*time.Second)
	}

	// Final sync
	logger.Debug("Final filesystem sync")
	exec.Command("sync").Run()
	time.Sleep(2 * time.Second)
	exec.Command("sync").Run()

	// EVALUATE - Log completion
	logger.Info("Data flush completed")

	return nil
}

// ExecuteReboot performs the actual system reboot
// Migrated from cmd/ragequit/ragequit.go executeReboot
func ExecuteReboot(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Verify we should reboot
	logger.Warn("Assessing reboot execution",
		zap.String("action", "SYSTEM_REBOOT"))

	// INTERVENE - Give final warning
	logger.Error("EXECUTING EMERGENCY REBOOT IN 10 SECONDS")
	fmt.Println("  EMERGENCY REBOOT IN 10 SECONDS  ")

	for i := 10; i > 0; i-- {
		fmt.Printf("%d... ", i)
		time.Sleep(1 * time.Second)
	}
	fmt.Println("\nREBOOTING NOW!")

	// Try multiple reboot methods
	logger.Info("Attempting system reboot")

	// Method 1: systemctl
	if err := exec.Command("systemctl", "reboot", "--force").Run(); err == nil {
		return nil
	}

	// Method 2: shutdown command
	if err := exec.Command("shutdown", "-r", "now").Run(); err == nil {
		return nil
	}

	// Method 3: reboot command
	if err := exec.Command("reboot", "-f").Run(); err == nil {
		return nil
	}

	// Method 4: Direct syscall (last resort)
	if err := exec.Command("echo", "b", ">", "/proc/sysrq-trigger").Run(); err == nil {
		return nil
	}

	// EVALUATE - If we get here, reboot failed
	return fmt.Errorf("all reboot methods failed")
}

// NotifyRagequit sends notifications about the ragequit
// Migrated from cmd/ragequit/ragequit.go notifyRagequit
func NotifyRagequit(rc *eos_io.RuntimeContext, reason string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Determine notification methods
	logger.Info("Assessing notification requirements")

	hostname := system.GetHostname()
	timestamp := time.Now().Format(time.RFC3339)
	message := fmt.Sprintf("EMERGENCY: Ragequit initiated on %s at %s. Reason: %s",
		hostname, timestamp, reason)

	// INTERVENE - Send notifications
	logger.Debug("Sending ragequit notifications")

	// Wall message to all logged-in users
	if system.CommandExists("wall") {
		wallMsg := fmt.Sprintf("\nEMERGENCY SYSTEM NOTIFICATION\n%s\n", message)
		exec.Command("wall", wallMsg).Run()
	}

	// System logger
	if system.CommandExists("logger") {
		exec.Command("logger", "-p", "emerg", "-t", "ragequit", message).Run()
	}

	// Write to /etc/motd for next login
	motdPath := "/etc/motd"
	if system.FileExists(motdPath) {
		motdMsg := fmt.Sprintf("\n=== RAGEQUIT RECOVERY ===\n%s\nSee ~/RAGEQUIT-RECOVERY-PLAN.md for details\n\n", message)
		if currentMotd, err := os.ReadFile(motdPath); err == nil {
			os.WriteFile(motdPath+".bak", currentMotd, 0644)
			os.WriteFile(motdPath, append([]byte(motdMsg), currentMotd...), 0644)
		}
	}

	// Email notification if mail is configured
	if system.CommandExists("mail") || system.CommandExists("sendmail") {
		// Try to send email to root
		emailCmd := exec.Command("sh", "-c",
			fmt.Sprintf("echo '%s' | mail -s 'RAGEQUIT: %s' root", message, hostname))
		emailCmd.Run()
	}

	// EVALUATE - Log notification status
	logger.Info("Notifications sent",
		zap.String("message", message))

	return nil
}
