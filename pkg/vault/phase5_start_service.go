// pkg/vault/vault_lifecycle.go

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

// StartVaultService ensures Vault systemd unit is enabled, started, and healthy.
func StartVaultService(log *zap.Logger) error {
	log.Info("🛠️ Writing Vault systemd unit file")
	if err := WriteSystemdUnit(log); err != nil {
		return fmt.Errorf("write systemd unit: %w", err)
	}

	log.Info("🔄 Reloading systemd daemon and enabling vault.service")
	if err := ReloadDaemonAndEnable(log, shared.VaultServiceName); err != nil {
		return fmt.Errorf("reload/enable vault.service: %w", err)
	}

	if err := ensureVaultDataDir(log); err != nil {
		return err
	}

	// validate config before touching systemd
	if err := ValidateVaultConfig(log); err != nil {
		log.Error("❌ Vault config validation failed — not starting service", zap.Error(err))
		return fmt.Errorf("vault config validation failed: %w", err)
	}

	log.Info("🚀 Starting Vault systemd service")
	if err := startVaultSystemdService(log); err != nil {
		log.Error("❌ Failed to start vault.service", zap.Error(err))
		captureVaultLogsOnFailure(log) // 👈 ADD THIS: show journal if start fails
		return fmt.Errorf("failed to start vault.service: %w", err)
	}

	return waitForVaultHealth(log, shared.VaultMaxHealthWait)
}

func WriteSystemdUnit(log *zap.Logger) error {
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

	log.Debug("✍️  Writing systemd unit", zap.String("path", shared.VaultAgentServicePath))
	if err := os.WriteFile(shared.VaultAgentServicePath,
		[]byte(strings.TrimSpace(unit)+"\n"),
		shared.FilePermStandard,
	); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}
	log.Info("✅ Systemd unit written", zap.String("path", shared.VaultAgentServicePath))
	return nil
}

// -> StartAndEnableService(name string) error
// utils.ReloadDaemonAndEnable reloads systemd, then enables & starts the given unit.
// It returns an error if either step fails.
func ReloadDaemonAndEnable(log *zap.Logger, unit string) error {
	// 1) reload systemd
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		log.Warn("systemd daemon-reload failed",
			zap.Error(err),
			zap.ByteString("output", out),
		)
		return fmt.Errorf("daemon-reload: %w", err)
	}

	// 2) enable & start the unit
	if out, err := exec.Command("systemctl", "enable", "--now", unit).CombinedOutput(); err != nil {
		log.Warn("failed to enable/start service",
			zap.String("unit", unit),
			zap.Error(err),
			zap.ByteString("output", out),
		)
		return fmt.Errorf("enable --now %s: %w", unit, err)
	}

	log.Info("✅ systemd unit enabled & started",
		zap.String("unit", unit),
	)
	return nil
}

// startVaultSystemdService starts Vault using systemctl safely.
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

// waitForVaultHealth repeatedly probes Vault's TCP port to ensure it becomes reachable within a given timeout.
func waitForVaultHealth(log *zap.Logger, maxWait time.Duration) error {
	log.Error("❌ Vault failed to start and listen on port", zap.Int("port", shared.VaultDefaultPortInt))
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
