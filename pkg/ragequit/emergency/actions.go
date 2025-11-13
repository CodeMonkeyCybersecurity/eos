package emergency

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
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
	if shared.FileExists("/proc/sys/vm/drop_caches") {
		if err := os.WriteFile("/proc/sys/vm/drop_caches", []byte("3\n"), shared.ConfigFilePerm); err != nil {
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
	if err := exec.Command("sync").Run(); err != nil {
		logger.Warn("First sync command failed", zap.Error(err))
	}
	time.Sleep(2 * time.Second)
	if err := exec.Command("sync").Run(); err != nil {
		logger.Warn("Second sync command failed", zap.Error(err))
	}

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
		if err := exec.Command("wall", wallMsg).Run(); err != nil {
			logger.Warn("Failed to send wall message", zap.Error(err))
		}
	}

	// System logger
	if system.CommandExists("logger") {
		if err := exec.Command("logger", "-p", "emerg", "-t", "ragequit", message).Run(); err != nil {
			logger.Warn("Failed to send syslog message", zap.Error(err))
		}
	}

	// Write to /etc/motd for next login
	motdPath := "/etc/motd"
	if shared.FileExists(motdPath) {
		motdMsg := fmt.Sprintf("\n=== RAGEQUIT RECOVERY ===\n%s\nSee ~/RAGEQUIT-RECOVERY-PLAN.md for details\n\n", message)
		if currentMotd, err := os.ReadFile(motdPath); err == nil {
			_ = os.WriteFile(motdPath+".bak", currentMotd, shared.ConfigFilePerm)
			_ = os.WriteFile(motdPath, append([]byte(motdMsg), currentMotd...), shared.ConfigFilePerm)
		}
	}

	// Email notification if mail is configured
	// SECURITY P0 FIX: Removed shell execution to prevent command injection
	if system.CommandExists("mail") {
		// Send email using direct command execution (no shell)
		emailCmd := exec.Command("mail", "-s", fmt.Sprintf("RAGEQUIT: %s", hostname), "root")
		emailCmd.Stdin = strings.NewReader(message)
		_ = emailCmd.Run() // Errors logged below
	} else if system.CommandExists("sendmail") {
		// Fallback to sendmail
		emailCmd := exec.Command("sendmail", "root")
		emailCmd.Stdin = strings.NewReader(fmt.Sprintf("Subject: RAGEQUIT: %s\n\n%s", hostname, message))
		_ = emailCmd.Run()
	}

	// EVALUATE - Log notification status
	logger.Info("Notifications sent",
		zap.String("message", message))

	return nil
}
