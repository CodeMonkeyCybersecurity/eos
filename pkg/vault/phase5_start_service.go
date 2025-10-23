// pkg/vault/phase5_start_service.go

package vault

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 5.  Install and Start vault.service
//--------------------------------------------------------------------

// StartVaultService()
//  ├── WriteVaultServerSystemdUnit()
//  ├── ValidateVaultConfig()   [⚠ external, not defined in this file]
//  ├── eos_unix.ReloadDaemonAndEnable()  [⚠ external]
//  ├── ensureVaultDataDir()    [⚠ external, not defined in this file]
//  ├── startVaultSystemdService()
//  └── waitForVaultHealth()

// WriteAgentSystemdUnit()

// WriteVaultServerSystemdUnit()

// startVaultSystemdService()

// waitForVaultHealth()
//  └── captureVaultLogsOnFailure()  [⚠ external]
//  └── shared.SafeClose()           [⚠ external]

// ValidateCriticalPaths()
//  └── eos_unix.LookupUser()          [⚠ external]

// StartVaultService installs, enables, and starts the Vault SERVER (vault.service).
func StartVaultService(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info(" Writing Vault SERVER systemd unit file")
	if err := WriteVaultServerSystemdUnit(rc); err != nil {
		return fmt.Errorf("write server systemd unit: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Validating Vault server config before starting")
	if err := ValidateVaultConfig(rc); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Vault config validation failed", zap.Error(err))
		return fmt.Errorf("vault config validation failed: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Reloading systemd daemon and enabling vault.service")
	if err := eos_unix.ReloadDaemonAndEnable(rc.Ctx, VaultServiceName); err != nil {
		return fmt.Errorf("reload/enable vault.service: %w", err)
	}

	if err := ensureVaultDataDir(rc); err != nil {
		return err
	}

	otelzap.Ctx(rc.Ctx).Info(" Starting Vault systemd service")
	if err := startVaultSystemdService(rc); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to start vault.service", zap.Error(err))
		captureVaultLogsOnFailure(rc)
		return fmt.Errorf("failed to start vault.service: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault systemd service started, checking health...")
	if err := waitForVaultHealth(rc, shared.VaultMaxHealthWait); err != nil {
		return err
	}

	return nil
}

func WriteVaultServerSystemdUnit(rc *eos_io.RuntimeContext) error {
	// Generate systemd unit with comprehensive security hardening from centralized constants
	svc := DefaultVaultService()

	// Build systemd unit using centralized security directives
	unit := fmt.Sprintf(`[Unit]
Description=HashiCorp Vault
Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=%s
StartLimitIntervalSec=%s
StartLimitBurst=%s

[Service]
Type=%s
User=%s
Group=%s
ExecStart=%s
ExecReload=/bin/kill -HUP $MAINPID
Restart=%s
RestartSec=%s
TimeoutStopSec=%s
KillMode=%s

# Resource Limits
LimitNOFILE=%s
LimitNPROC=%s
LimitMEMLOCK=%s

# Linux Capabilities
CapabilityBoundingSet=%s
AmbientCapabilities=%s
SecureBits=%s
NoNewPrivileges=%s

# Filesystem Sandboxing
ProtectSystem=%s
ReadWritePaths=%s
ProtectHome=%s
PrivateTmp=%s
PrivateDevices=%s

# Kernel Protections
ProtectKernelTunables=%s
ProtectKernelModules=%s
ProtectKernelLogs=%s
ProtectControlGroups=%s

# Process Restrictions
RestrictRealtime=%s
RestrictNamespaces=%s
RestrictAddressFamilies=%s

# Memory Protection
MemoryDenyWriteExecute=%s
LockPersonality=%s

# Logging
StandardOutput=%s
StandardError=%s

[Install]
WantedBy=multi-user.target
`,
		VaultConfigPath,
		VaultSystemdStartLimitInterval,
		VaultSystemdStartLimitBurst,
		VaultSystemdServiceType,
		svc.User,
		svc.Group,
		svc.ExecStartCommand(),
		VaultSystemdRestart,
		VaultSystemdRestartSec,
		VaultSystemdTimeoutStopSec,
		VaultSystemdKillMode,
		VaultSystemdLimitNOFILE,
		VaultSystemdLimitNPROC,
		VaultSystemdLimitMEMLOCK,
		VaultSystemdCapabilityBoundingSet,
		VaultSystemdAmbientCapabilities,
		VaultSystemdSecureBits,
		VaultSystemdNoNewPrivileges,
		VaultSystemdProtectSystem,
		VaultSystemdReadWritePaths,
		VaultSystemdProtectHome,
		VaultSystemdPrivateTmp,
		VaultSystemdPrivateDevices,
		VaultSystemdProtectKernelTunables,
		VaultSystemdProtectKernelModules,
		VaultSystemdProtectKernelLogs,
		VaultSystemdProtectControlGroups,
		VaultSystemdRestrictRealtime,
		VaultSystemdRestrictNamespaces,
		VaultSystemdRestrictAddressFamilies,
		VaultSystemdMemoryDenyWriteExecute,
		VaultSystemdLockPersonality,
		VaultSystemdStandardOutput,
		VaultSystemdStandardError,
	)

	err := os.WriteFile(VaultServicePath, []byte(unit), shared.FilePermStandard)
	if err != nil {
		return fmt.Errorf("write vault server unit: %w", err)
	}
	otelzap.Ctx(rc.Ctx).Info(" Vault server systemd unit written",
		zap.String("path", VaultServicePath),
		zap.String("binary", VaultBinaryPath),
		zap.String("config", VaultConfigPath),
		zap.String("read_write_paths", VaultSystemdReadWritePaths))
	return nil
}

// startVaultSystemdService safely starts the vault.service.
func startVaultSystemdService(rc *eos_io.RuntimeContext) error {

	cmd := exec.CommandContext(rc.Ctx, "systemctl", "start", VaultServiceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to start vault.service", zap.Error(err))
		return fmt.Errorf("failed to start vault.service: %w", err)
	}
	return nil
}

// waitForVaultHealth probes Vault's TCP port until healthy or timeout.
func waitForVaultHealth(rc *eos_io.RuntimeContext, maxWait time.Duration) error {
	otelzap.Ctx(rc.Ctx).Info(" Waiting for Vault to start listening on port", zap.Int("port", shared.VaultDefaultPortInt))
	start := time.Now()
	for {
		if time.Since(start) > maxWait {
			captureVaultLogsOnFailure(rc)
			return fmt.Errorf("vault did not become healthy within %s", maxWait)
		}
		conn, err := net.DialTimeout("tcp", shared.GetVaultHostPort(), shared.VaultRetryDelay)
		if err == nil {
			defer shared.SafeClose(rc.Ctx, conn)
			otelzap.Ctx(rc.Ctx).Info(" Vault is now listening", zap.Duration("waited", time.Since(start)))
			return nil
		}
		otelzap.Ctx(rc.Ctx).Debug(" Vault still not listening, retrying...", zap.Duration("waited", time.Since(start)))
		// SECURITY P2 #7: Use context-aware sleep to respect cancellation
		select {
		case <-time.After(shared.VaultRetryDelay):
			// Continue waiting
		case <-rc.Ctx.Done():
			return fmt.Errorf("vault listener check cancelled after %s: %w", time.Since(start), rc.Ctx.Err())
		}
	}
}

// ValidateCriticalPaths checks that Vault critical directories are owned and writable by the service user.
func ValidateCriticalPaths(rc *eos_io.RuntimeContext) error {
	criticalPaths := []string{
		shared.VaultDataPath, // /opt/vault/data
	}

	// Use vault user instead of deprecated eos user
	vaultUID, vaultGID, err := eos_unix.LookupUser(rc.Ctx, "vault")
	if err != nil {
		// If vault user doesn't exist, skip validation
		otelzap.Ctx(rc.Ctx).Info("Vault user not found, skipping path validation")
		return nil
	}

	for _, path := range criticalPaths {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("failed to stat critical path %s: %w", path, err)
		}

		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("unexpected stat type for path %s", path)
		}

		if int(st.Uid) != vaultUID || int(st.Gid) != vaultGID {
			return fmt.Errorf("ownership mismatch on %s: want uid=%d gid=%d, got uid=%d gid=%d",
				path, vaultUID, vaultGID, st.Uid, st.Gid)
		}

		// Check writable bit
		if info.Mode().Perm()&0200 == 0 {
			return fmt.Errorf("critical path %s is not writable (permissions %#o)", path, info.Mode().Perm())
		}

		otelzap.Ctx(rc.Ctx).Info(" Critical path validated", zap.String("path", path))
	}

	return nil
}
