package recovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreatePostRebootRecovery creates a post-reboot recovery script
// Migrated from cmd/ragequit/ragequit.go createPostRebootRecovery
func CreatePostRebootRecovery(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare recovery script creation
	logger.Info("Assessing post-reboot recovery requirements")

	homeDir := system.GetHomeDir()
	scriptFile := filepath.Join(homeDir, "post-ragequit-recovery.sh")

	// INTERVENE - Create recovery script
	logger.Debug("Creating post-reboot recovery script")

	script := `#!/bin/bash
# Auto-run after ragequit reboot

echo "=== Post-Ragequit Recovery Starting ==="
date

# Check if we just came from a ragequit
if [ -f ~/ragequit-timestamp.txt ]; then
    echo "System rebooted after ragequit event:"
    cat ~/ragequit-timestamp.txt
    
    # Archive the diagnostic files
    ARCHIVE_DIR="$HOME/ragequit-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$ARCHIVE_DIR"
    mv ~/ragequit-*.txt ~/*.backup "$ARCHIVE_DIR/" 2>/dev/null || true
    
    # Check systemd health
    echo -e "\nSystemd health check:"
    systemctl is-system-running
    ps -p 1 -o %cpu,etime
    
    # Check for failed services
    echo -e "\nFailed services:"
    systemctl list-units --failed --no-pager
    
    # Check disk space
    echo -e "\nDisk space:"
    df -h /
    
    # Archive the timestamp to prevent re-runs
    mv ~/ragequit-timestamp.txt "$ARCHIVE_DIR/" 2>/dev/null || true
    
    echo -e "\nRecovery complete. See ~/RAGEQUIT-RECOVERY-PLAN.md for next steps."
    echo "Diagnostic files archived in: $ARCHIVE_DIR"
else
    echo "Normal boot detected (no ragequit timestamp found)"
fi
`

	if err := os.WriteFile(scriptFile, []byte(script), 0755); err != nil {
		return fmt.Errorf("failed to create post-reboot recovery script: %w", err)
	}

	logger.Info("Post-reboot recovery script created",
		zap.String("script_file", scriptFile))

	// Add to user's profile for auto-execution
	profileFile := filepath.Join(homeDir, ".bashrc")
	profileEntry := "\n# Auto-run ragequit recovery check\n[ -f ~/ragequit-timestamp.txt ] && ~/post-ragequit-recovery.sh\n"

	// Check if entry already exists
	if content := system.ReadFile(profileFile); content != "" && !strings.Contains(content, "post-ragequit-recovery.sh") {
		file, err := os.OpenFile(profileFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			logger.Warn("Failed to open .bashrc for update",
				zap.String("file", profileFile),
				zap.Error(err))
		} else {
			defer func() {
				if closeErr := file.Close(); closeErr != nil {
					logger.Error("Failed to close .bashrc file", zap.Error(closeErr))
				}
			}()

			if _, err := file.WriteString(profileEntry); err != nil {
				logger.Warn("Failed to write to .bashrc",
					zap.String("file", profileFile),
					zap.Error(err))
			} else {
				logger.Info("Added post-reboot hook to .bashrc",
					zap.String("file", profileFile))
			}
		}
	} else if strings.Contains(content, "post-ragequit-recovery.sh") {
		logger.Debug("Post-reboot hook already exists in .bashrc")
	}

	// EVALUATE - Log completion
	logger.Info("Post-reboot recovery setup completed",
		zap.String("script", scriptFile),
		zap.String("profile", profileFile))

	return nil
}
