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

// PHASE 5 — StartVaultService()
//             └── WriteSystemdUnit()
//             └── ReloadDaemonAndEnable()
//             └── startVaultSystemdService()
//             └── waitForVaultHealth()

// StartVaultService installs, enables, and starts the Vault SERVER (vault.service).
func StartVaultService(log *zap.Logger) error {
	log.Info("🛠️ Writing Vault SERVER systemd unit file")
	if err := WriteVaultServerSystemdUnit(log); err != nil {
		return fmt.Errorf("write server systemd unit: %w", err)
	}

	log.Info("🛠️ Validating Vault server config before starting")
	if err := ValidateVaultConfig(log); err != nil {
		log.Error("❌ Vault config validation failed", zap.Error(err))
		return fmt.Errorf("vault config validation failed: %w", err)
	}

	log.Info("🔄 Reloading systemd daemon and enabling vault.service")
	if err := system.ReloadDaemonAndEnable(log, shared.VaultServiceName); err != nil {
		return fmt.Errorf("reload/enable vault.service: %w", err)
	}

	if err := ensureVaultDataDir(log); err != nil {
		return err
	}

	log.Info("🚀 Starting Vault systemd service")
	if err := startVaultSystemdService(log); err != nil {
		log.Error("❌ Failed to start vault.service", zap.Error(err))
		captureVaultLogsOnFailure(log)
		return fmt.Errorf("failed to start vault.service: %w", err)
	}

	log.Info("✅ Vault systemd service started, checking health...")
	return waitForVaultHealth(log, shared.VaultMaxHealthWait)
}

func WriteAgentSystemdUnit(log *zap.Logger) error {
	unit := fmt.Sprintf(shared.AgentSystemDUnit,
		shared.VaultAgentUser,
		shared.VaultAgentGroup,
		shared.VaultRuntimePerms,
		shared.VaultAgentUser,
		shared.VaultAgentGroup,
		shared.VaultRuntimePerms,
		shared.EosRunDir,
		shared.VaultAgentConfigPath,
	)

	log.Debug("✍️ Writing Vault AGENT systemd unit", zap.String("path", shared.VaultAgentServicePath))
	if err := os.WriteFile(shared.VaultAgentServicePath,
		[]byte(strings.TrimSpace(unit)+"\n"),
		shared.FilePermStandard,
	); err != nil {
		return fmt.Errorf("write agent unit file: %w", err)
	}
	log.Info("✅ Vault agent systemd unit written", zap.String("path", shared.VaultAgentServicePath))
	return nil
}

func WriteVaultServerSystemdUnit(log *zap.Logger) error {
	unit := strings.TrimSpace(shared.ServerSystemDUnit) + "\n"
	err := os.WriteFile(shared.VaultServicePath, []byte(unit), shared.FilePermStandard)
	if err != nil {
		return fmt.Errorf("write vault server unit: %w", err)
	}
	log.Info("✅ Vault server systemd unit written", zap.String("path", shared.VaultServicePath))
	return nil
}

// startVaultSystemdService safely starts the vault.service.
func startVaultSystemdService(log *zap.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "start", shared.VaultServiceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Error("❌ Failed to start vault.service", zap.Error(err))
		return fmt.Errorf("failed to start vault.service: %w", err)
	}
	return nil
}

// waitForVaultHealth probes Vault's TCP port until healthy or timeout.
func waitForVaultHealth(log *zap.Logger, maxWait time.Duration) error {
	log.Info("⏳ Waiting for Vault to start listening on port", zap.Int("port", shared.VaultDefaultPortInt))
	start := time.Now()
	for {
		if time.Since(start) > maxWait {
			captureVaultLogsOnFailure(log)
			return fmt.Errorf("vault did not become healthy within %s", maxWait)
		}
		conn, err := net.DialTimeout("tcp", shared.ListenerAddr, shared.VaultRetryDelay)
		if err == nil {
			conn.Close()
			log.Info("✅ Vault is now listening", zap.Duration("waited", time.Since(start)))
			return nil
		}
		log.Debug("⏳ Vault still not listening, retrying...", zap.Duration("waited", time.Since(start)))
		time.Sleep(shared.VaultRetryDelay)
	}
}

// ValidateCriticalPaths checks that Vault critical directories are owned and writable by the service user.
func ValidateCriticalPaths(log *zap.Logger) error {
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

		log.Info("✅ Critical path validated", zap.String("path", path))
	}

	return nil
}
