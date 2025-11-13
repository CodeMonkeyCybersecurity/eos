//go:build linux

package disk

import (
	"context"
	"fmt"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"libvirt.org/go/libvirt"
)

// GuestManager handles operations inside the guest OS
type GuestManager struct{}

// ResizeFilesystem resizes the filesystem inside the guest OS
func (gm *GuestManager) ResizeFilesystem(ctx context.Context, assessment *Assessment) error {
	logger := otelzap.Ctx(ctx)

	if !assessment.HasGuestAgent {
		return fmt.Errorf("guest agent not available")
	}

	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	domain, err := conn.LookupDomainByName(assessment.VMName)
	if err != nil {
		return fmt.Errorf("VM not found: %w", err)
	}
	defer func() { _ = domain.Free() }()

	// Detect guest OS type
	guestOS := assessment.GuestOS
	if guestOS == "" {
		guestOS = "linux" // Default assumption
	}

	logger.Info("Resizing guest filesystem",
		zap.String("vm", assessment.VMName),
		zap.String("os", guestOS))

	switch guestOS {
	case "linux", "":
		return gm.resizeLinuxFilesystem(ctx, domain, assessment)
	case "windows":
		return fmt.Errorf("Windows filesystem resize not yet implemented - manual steps required")
	default:
		return fmt.Errorf("unsupported guest OS: %s", guestOS)
	}
}

func (gm *GuestManager) resizeLinuxFilesystem(ctx context.Context, domain *libvirt.Domain, assessment *Assessment) error {
	logger := otelzap.Ctx(ctx)

	// Common Linux resize sequence:
	// 1. growpart (extend partition)
	// 2. pvresize (if LVM)
	// 3. lvextend (if LVM)
	// 4. filesystem resize (xfs_growfs or resize2fs)

	commands := []string{
		// Try to grow partition (may fail if already max size - that's ok)
		"growpart /dev/vda 2 || true",
	}

	// If LVM detected, add LVM commands
	if assessment.LVMDetected {
		commands = append(commands,
			"pvresize /dev/vda2 || true",
			"lvextend -l +100%FREE /dev/mapper/*-root || lvextend -l +100%FREE /dev/mapper/*-lv_root || true",
		)
	}

	// Detect and resize filesystem
	// Try both XFS and ext4 (one will work, one will fail - that's ok)
	commands = append(commands,
		"xfs_growfs / || resize2fs /dev/mapper/*-root || resize2fs /dev/vda* || true",
	)

	// Execute commands via guest agent
	for _, cmd := range commands {
		logger.Debug("Executing in guest", zap.String("command", cmd))

		// Use guest-exec command
		execCmd := fmt.Sprintf(`{"execute":"guest-exec","arguments":{"path":"/bin/sh","arg":["-c","%s"],"capture-output":true}}`, cmd)

		result, err := domain.QemuAgentCommand(
			execCmd,
			libvirt.DomainQemuAgentCommandTimeout(30),
			0,
		)

		if err != nil {
			logger.Warn("Guest command failed (may be expected)",
				zap.String("command", cmd),
				zap.Error(err))
			continue
		}

		logger.Debug("Guest command result", zap.String("result", result))
	}

	logger.Info("Guest filesystem resize commands executed",
		zap.String("note", "Some commands may have failed - this is expected"))

	return nil
}
