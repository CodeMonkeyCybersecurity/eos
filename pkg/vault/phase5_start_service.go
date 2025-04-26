// pkg/vault/phase5_start_service.go

package vault

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
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
	if err := ReloadDaemonAndEnable(log, shared.VaultServiceName); err != nil {
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

// StartVaultAgentService installs, enables, and starts the Vault AGENT (vault-agent-eos.service).
func StartVaultAgentService(log *zap.Logger) error {
	log.Info("🛠️ Writing Vault AGENT systemd unit file")
	if err := WriteAgentSystemdUnit(log); err != nil {
		return fmt.Errorf("write agent systemd unit: %w", err)
	}

	log.Info("🔄 Reloading systemd daemon and enabling vault-agent-eos.service")
	if err := ReloadDaemonAndEnable(log, shared.VaultAgentService); err != nil {
		return fmt.Errorf("reload/enable vault-agent-eos.service: %w", err)
	}

	log.Info("✅ Vault agent systemd service installed and started")
	return nil
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

// ReloadDaemonAndEnable reloads systemd, enables, and starts the given unit.
func ReloadDaemonAndEnable(log *zap.Logger, unit string) error {
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		log.Warn("systemd daemon-reload failed", zap.Error(err), zap.ByteString("output", out))
		return fmt.Errorf("daemon-reload: %w", err)
	}

	if out, err := exec.Command("systemctl", "enable", "--now", unit).CombinedOutput(); err != nil {
		log.Warn("failed to enable/start service", zap.String("unit", unit), zap.Error(err), zap.ByteString("output", out))
		return fmt.Errorf("enable --now %s: %w", unit, err)
	}

	log.Info("✅ systemd unit enabled & started", zap.String("unit", unit))
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
