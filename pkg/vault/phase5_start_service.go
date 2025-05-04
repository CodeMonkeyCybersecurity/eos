// pkg/vault/phase5_start_service.go

package vault

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 5.  Install and Start vault.service
//--------------------------------------------------------------------

// StartVaultService()
//  ├── WriteVaultServerSystemdUnit()
//  ├── ValidateVaultConfig()   [⚠ external, not defined in this file]
//  ├── system.ReloadDaemonAndEnable()  [⚠ external]
//  ├── ensureVaultDataDir()    [⚠ external, not defined in this file]
//  ├── startVaultSystemdService()
//  ├── waitForVaultHealth()
//  └── PrintNextSteps()        [⚠ external, added from your new function]

// WriteAgentSystemdUnit()

// WriteVaultServerSystemdUnit()

// startVaultSystemdService()

// waitForVaultHealth()
//  └── captureVaultLogsOnFailure()  [⚠ external]
//  └── shared.SafeClose()           [⚠ external]

// ValidateCriticalPaths()
//  └── system.LookupUser()          [⚠ external]

// StartVaultService installs, enables, and starts the Vault SERVER (vault.service).
func StartVaultService() error {
	zap.L().Info("🛠️ Writing Vault SERVER systemd unit file")
	if err := WriteVaultServerSystemdUnit(); err != nil {
		return fmt.Errorf("write server systemd unit: %w", err)
	}

	zap.L().Info("🛠️ Validating Vault server config before starting")
	if err := ValidateVaultConfig(); err != nil {
		zap.L().Error("❌ Vault config validation failed", zap.Error(err))
		return fmt.Errorf("vault config validation failed: %w", err)
	}

	zap.L().Info("🔄 Reloading systemd daemon and enabling vault.service")
	if err := system.ReloadDaemonAndEnable(shared.VaultServiceName); err != nil {
		return fmt.Errorf("reload/enable vault.service: %w", err)
	}

	if err := ensureVaultDataDir(); err != nil {
		return err
	}

	zap.L().Info("🚀 Starting Vault systemd service")
	if err := startVaultSystemdService(); err != nil {
		zap.L().Error("❌ Failed to start vault.service", zap.Error(err))
		captureVaultLogsOnFailure()
		return fmt.Errorf("failed to start vault.service: %w", err)
	}

	zap.L().Info("✅ Vault systemd service started, checking health...")
	if err := waitForVaultHealth(shared.VaultMaxHealthWait); err != nil {
		return err
	}

	// ✅ Print user instructions here
	PrintNextSteps()

	return nil
}

func WriteAgentSystemdUnit() error {
	unit := fmt.Sprintf(shared.AgentSystemDUnit,
		shared.VaultAgentUser,
		shared.VaultAgentGroup,
		shared.RuntimeDirPerms,
		shared.VaultAgentUser,
		shared.VaultAgentGroup,
		shared.RuntimeDirPerms,
		shared.EosRunDir,
		shared.VaultAgentConfigPath,
	)

	zap.L().Debug("✍️ Writing Vault AGENT systemd unit", zap.String("path", shared.VaultAgentServicePath))
	if err := os.WriteFile(shared.VaultAgentServicePath,
		[]byte(strings.TrimSpace(unit)+"\n"),
		shared.FilePermStandard,
	); err != nil {
		return fmt.Errorf("write agent unit file: %w", err)
	}
	zap.L().Info("✅ Vault agent systemd unit written", zap.String("path", shared.VaultAgentServicePath))
	return nil
}

func WriteVaultServerSystemdUnit() error {
	unit := strings.TrimSpace(shared.ServerSystemDUnit) + "\n"
	err := os.WriteFile(shared.VaultServicePath, []byte(unit), shared.FilePermStandard)
	if err != nil {
		return fmt.Errorf("write vault server unit: %w", err)
	}
	zap.L().Info("✅ Vault server systemd unit written", zap.String("path", shared.VaultServicePath))
	return nil
}

// startVaultSystemdService safely starts the vault.service.
func startVaultSystemdService() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "start", shared.VaultServiceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		zap.L().Error("❌ Failed to start vault.service", zap.Error(err))
		return fmt.Errorf("failed to start vault.service: %w", err)
	}
	return nil
}

// waitForVaultHealth probes Vault's TCP port until healthy or timeout.
func waitForVaultHealth(maxWait time.Duration) error {
	zap.L().Info("⏳ Waiting for Vault to start listening on port", zap.Int("port", shared.VaultDefaultPortInt))
	start := time.Now()
	for {
		if time.Since(start) > maxWait {
			captureVaultLogsOnFailure()
			return fmt.Errorf("vault did not become healthy within %s", maxWait)
		}
		conn, err := net.DialTimeout("tcp", shared.ListenerAddr, shared.VaultRetryDelay)
		if err == nil {
			defer shared.SafeClose(conn)
			zap.L().Info("✅ Vault is now listening", zap.Duration("waited", time.Since(start)))
			return nil
		}
		zap.L().Debug("⏳ Vault still not listening, retrying...", zap.Duration("waited", time.Since(start)))
		time.Sleep(shared.VaultRetryDelay)
	}
}

// ValidateCriticalPaths checks that Vault critical directories are owned and writable by the service user.
func ValidateCriticalPaths() error {
	criticalPaths := []string{
		shared.VaultDataPath, // /opt/vault/data
	}

	eosUID, eosGID, err := system.LookupUser(shared.EosUser)
	if err != nil {
		return fmt.Errorf("failed to resolve eos user UID/GID: %w", err)
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

		if int(st.Uid) != eosUID || int(st.Gid) != eosGID {
			return fmt.Errorf("ownership mismatch on %s: want uid=%d gid=%d, got uid=%d gid=%d",
				path, eosUID, eosGID, st.Uid, st.Gid)
		}

		// Check writable bit
		if info.Mode().Perm()&0200 == 0 {
			return fmt.Errorf("critical path %s is not writable (permissions %#o)", path, info.Mode().Perm())
		}

		zap.L().Info("✅ Critical path validated", zap.String("path", path))
	}

	return nil
}
