// pkg/vault/vault_lifecycle.go

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// PhaseEnsureClientHealthy makes sure we can reach a healthy Vault
// instance, and if not, attempts init / unseal flows automatically.
func PhaseEnsureClientHealthy(log *zap.Logger) error {
	log.Info("[4/6] Ensuring Vault client is available and healthy")

	//--------------------------------------------------------------------
	// 0. Fast‑path: is something already listening on 8179 as eos/vault?
	//--------------------------------------------------------------------
	if out, _ := exec.Command("lsof", "-i", shared.VaultDefaultPort).Output(); len(out) > 0 {
		log.Info("📡 Detected process on port 8179",
			zap.String("output", string(out)))

		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "vault") && strings.Contains(line, shared.EosUser) {
				log.Info("✅ Vault already running as 'eos' – skipping health loop")
				return nil
			}
		}
		log.Info("ℹ️ Port 8179 is in use (but not vault:eos) – continuing with SDK check")
	}

	//--------------------------------------------------------------------
	// 1.  Sanity: VAULT_ADDR and binary
	//--------------------------------------------------------------------
	if _, err := EnsureVaultEnv(log); err != nil {
		return fmt.Errorf("could not determine Vault address: %w", err)
	}
	if _, err := exec.LookPath("vault"); err != nil {
		return fmt.Errorf("vault binary not installed or not in $PATH")
	}

	//--------------------------------------------------------------------
	// 2.  Health‑check / bootstrap loop (max 5 attempts)
	//--------------------------------------------------------------------
	client, err := NewClient(log)
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	for attempt := 1; attempt <= 5; attempt++ {
		log.Info("🔁 Vault health probe",
			zap.Int("attempt", attempt))

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		resp, err := client.Sys().HealthWithContext(ctx)
		cancel() // no defer inside the loop

		if err != nil {
			log.Warn("🔌 Health request failed – retrying",
				zap.Error(err))
			time.Sleep(shared.VaultRetryDelay)
			continue
		}

		switch {
		case resp.Initialized && !resp.Sealed && !resp.Standby: // healthy & unsealed
			log.Info("✅ Vault is initialised and unsealed",
				zap.String("version", resp.Version))
			return nil

		case !resp.Initialized: // not initialised
			log.Info("ℹ️ Vault reports uninitialised (501) – running init flow")
			if err := initAndUnseal(client, log); err != nil {
				return fmt.Errorf("init/unseal failed: %w", err)
			}
			return nil

		case resp.Initialized && resp.Sealed: // sealed
			log.Info("🔒 Vault reports sealed (503) – attempting auto‑unseal")
			if err := unsealFromStoredKeys(client, log); err != nil {
				return fmt.Errorf("auto‑unseal failed: %w", err)
			}
			return nil

		case resp.Standby: // standby
			log.Info("🟡 Vault is in standby – treating as healthy for CLI")
			return nil

		default:
			log.Warn("⚠️ Unexpected health state",
				zap.Any("response", resp))
			time.Sleep(shared.VaultRetryDelay)
			return err
		}
	}
	return fmt.Errorf("vault not healthy after multiple attempts")
}

func PhaseApplyCoreSecrets(client *api.Client, kvPath string, kvData map[string]string, log *zap.Logger) error {
	log.Info("[6/6] Applying core secrets to Vault", zap.String("path", kvPath))

	kv := client.KVv2("secret")

	// Sanity check: avoid nil maps
	if kvData == nil {
		log.Warn("No data provided for secret — initializing empty map")
		kvData = make(map[string]string)
	}

	// Marshal as {"json": "..."}
	data, err := json.Marshal(kvData)
	if err != nil {
		return fmt.Errorf("failed to marshal KV data: %w", err)
	}
	payload := map[string]interface{}{"json": string(data)}

	// Write to Vault
	if _, err := kv.Put(context.Background(), kvPath, payload); err != nil {
		return fmt.Errorf("failed to write secret at %s: %w", kvPath, err)
	}

	log.Info("✅ Secret written to Vault", zap.String("path", kvPath), zap.Int("keys", len(kvData)))
	return nil
}

// Purge removes Vault repo artifacts and paths based on the Linux distro.
// It returns a list of removed files and a map of errors keyed by path.
func Purge(distro string, log *zap.Logger) (removed []string, errs map[string]error) {
	errs = make(map[string]error)
	log.Info("🧹 Starting full Vault purge sequence", zap.String("distro", distro))

	pathsToRemove := []string{}

	switch distro {
	case "debian":
		pathsToRemove = append(pathsToRemove, shared.AptKeyringPath, shared.AptListPath)
	case "rhel":
		pathsToRemove = append(pathsToRemove, shared.DnfRepoFilePath)
	default:
		log.Warn("⚠️ No package manager cleanup defined for distro", zap.String("distro", distro))
	}

	pathsToRemove = append(pathsToRemove, shared.VaultBinaryPath)

	for _, path := range pathsToRemove {
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				log.Info("ℹ️ File already absent", zap.String("path", path))
				continue
			}
			log.Error("❌ Failed to remove file", zap.String("path", path), zap.Error(err))
			errs[path] = fmt.Errorf("failed to remove %s: %w", path, err)
		} else {
			log.Info("✅ Removed file", zap.String("path", path))
			removed = append(removed, path)
		}
	}

	// Safe systemd reload with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := exec.CommandContext(ctx, "systemctl", "daemon-reexec").Run(); err != nil {
		log.Warn("⚠️ Failed daemon-reexec", zap.Error(err))
	}
	if err := exec.CommandContext(ctx, "systemctl", "daemon-reload").Run(); err != nil {
		log.Warn("⚠️ Failed daemon-reload", zap.Error(err))
	}

	log.Info("✅ Vault purge complete", zap.Int("paths_removed", len(removed)), zap.Int("errors", len(errs)))
	return removed, errs
}

// VaultDelete removes a secret at the given KV v2 path
func VaultDelete(path string, log *zap.Logger) error {
	client, err := GetPrivilegedVaultClient(log)
	if err != nil {
		return err
	}
	kv := client.KVv2("secret")
	return kv.Delete(context.Background(), path)
}

// VaultDestroy permanently deletes a secret at the given KV v2 path
func VaultPurge(path string, log *zap.Logger) error {
	client, err := GetPrivilegedVaultClient(log)
	if err != nil {
		return err
	}
	kv := client.KVv2("secret")
	return kv.Destroy(context.Background(), path, []int{1}) // TODO To truly destroy all versions, we can add a version-walk helper
}

/**/
// ✅ This ensures that **every elevation boundary is explicit and auditable**, and EOS remains thin and Unix-idiomatic.
// ---
// ### Decision: vault.hcl Configuration
// - **Port**: Use `8179` as the Vault listener port.
//   - Reason: Avoid conflicts with default `8200`, fits into a prime-number port scheme.
// - **Listener Address**: Bind to `0.0.0.0`, but firewall access by default.
//   - Allows LAN/local trust zone use while maintaining sensible defaults.
// - **Storage Backend**: Use file backend, stored under `/opt/vault/data` (EOS Vault home).
// - **Log Level**: Use `debug` logging by default for now.
//   - Intentional for early-stage troubleshooting across EOS CLI.
//   - Will disable/override in future `eos bootstrap` or packaging command.
// - **Templating**: Decision pending — requires clarification between "Go templating" and "static embedding".
/**/

/**/
//  GetInternalHostname, AllowPorts, RequireLinuxDistro, GetOSPlatform and DetectLinuxDistro are from the platform.* helpers
// For simplicity, they are not includeed here
/**/

/**/
// TODO: Confirm function
// ## 2. Detect and Set Vault Environment
// Just resolves VAULT_ADDR
//     - Tries VAULT_ADDR env var
//     - Falls back to shared.ListenerAddr
//     - Falls back to internal hostname
//  1. Prefer an existing HTTPS listener on 127.0.0.1:<VaultDefaultPort>
//  2. Else try https://<internal‑hostname>:<VaultDefaultPort>
//  3. Else fall back to the hostname form so callers have *something*

/**/
// TODO: Confirm function
// ## 4. Render and Write vault.hcl Config
// ### Decision: Use Go Text Templates for vault.hcl
// - EOS will render `vault.hcl` using `text/template` with a runtime map.
// - Paths such as TLS certs, storage location, and listener address will be populated dynamically.
// - Enables user overrides via flags and makes the config more testable and composable.
// - Maintains alignment with Unix philosophy and Go idioms (text as interface).
// ---

/**/
// TODO: WriteVaultConfig(config []byte, log *zap.Logger) error
// ### Decision: Use Go Text Templates for vault.hcl
// - EOS will render `vault.hcl` using `text/template` with a runtime map.
// - Paths such as TLS certs, storage location, and listener address will be populated dynamically.
// - Enables user overrides via flags and makes the config more testable and composable.
// - Maintains alignment with Unix philosophy and Go idioms (text as interface).
//if err := stepCopyCA(log); err != nil { ... }                           // step 6
// Agent creation logic now called after PhaseApplycoreSecrets is this appropriate??
// ---

/**/
// TODO: RenderVaultServiceUnit() ([]byte, error)
/**/

// ensureVaultDataDir ensures the Vault data directory exists.
func ensureVaultDataDir(log *zap.Logger) error {
	dataPath := shared.VaultDataPath
	if err := os.MkdirAll(dataPath, 0700); err != nil {
		log.Error("❌ Failed to create Vault data dir", zap.String("path", dataPath), zap.Error(err))
		return fmt.Errorf("failed to create Vault data dir: %w", err)
	}
	log.Info("✅ Vault data directory ready", zap.String("path", dataPath))
	return nil
}

// captureVaultLogsOnFailure captures the last 20 lines of Vault's systemd journal logs for debugging purposes.
func captureVaultLogsOnFailure(log *zap.Logger) {
	log.Warn("💡 Hint: Run 'systemctl status vault' or 'journalctl -u vault' to diagnose Vault startup issues")
	out, err := exec.Command("journalctl", "-u", "vault", "-n", "20", "--no-pager").CombinedOutput()
	if err != nil {
		log.Warn("⚠️ Failed to capture Vault journal logs", zap.Error(err))
		return
	}
	log.Error("🚨 Vault systemd logs", zap.String("logs", string(out)))
}
