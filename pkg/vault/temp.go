// pkg/vault/temp.go

package vault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

func RequireVault(client *api.Client) error {
	if client == nil {
		zap.L().Error("❌ Vault client is nil", zap.String("reason", "Vault is required but not initialized"))
		return fmt.Errorf("vault is required for this command, but not available")
	}

	zap.L().Debug("✅ Vault client is present and usable")
	return nil
}

// ConfirmSecureStorage prompts user to re-enter keys to confirm they've been saved.
func ConfirmSecureStorage(original *api.InitResponse) error {
	fmt.Println("🔒 Please re-enter 3 unseal keys and the root token to confirm you've saved them.")

	rekeys, err := interaction.PromptSecrets("Unseal Key", 3)
	if err != nil {
		return err
	}
	reroot, err := interaction.PromptSecrets("Root Token", 1)
	if err != nil {
		return err
	}

	// Match at least 3 keys
	matched := 0
	for _, input := range rekeys {
		for _, ref := range original.KeysB64 {
			if crypto.HashString(input) == crypto.HashString(ref) {
				matched++
				break
			}
		}
	}
	if matched < 3 || crypto.HashString(reroot[0]) != crypto.HashString(original.RootToken) {
		return fmt.Errorf("reconfirmation failed: keys or token do not match")
	}

	zap.L().Info("✅ Reconfirmation of unseal material passed")
	return nil
}

// ResolveVaultConfigDir returns the Vault config directory based on Linux distro.
func ResolveVaultConfigDir(distro string) string {
	switch distro {
	case "debian", "rhel":
		return shared.VaultConfigDirDebian
	default:
		return shared.VaultConfigDirDebian // future: handle other distros here
	}
}

// Make this the go-to for Step 2. Keep EnsureVault(...) clean by calling this inline.
func EnsureVaultUserLifecycle(client *api.Client) error {
	if err := system.EnsureEosUser(true, false); err != nil {
		return err
	}
	if err := EnsureVaultDirs(); err != nil {
		return err
	}
	if err := system.EnsureSudoersEntryForEos(true); err != nil {
		return err
	}
	if err := EnsureVaultAuthMethods(client); err != nil {
		return err
	}

	if err := system.ValidateEosSudoAccess(); err != nil {
		return err

	}
	_, _, err := EnsureAppRole(client, DefaultAppRoleOptions())
	return err
}

// PromptForUnsealAndRoot prompts the user for 3 unseal keys and 1 root token.
// Returns an error if input reading fails.
func PromptForUnsealAndRoot() (api.InitResponse, error) {
	zap.L().Info("Prompting for unseal keys and root token")
	fmt.Println("🔐 Please enter 3 unseal keys and the root token")

	keys, err := interaction.PromptSecrets("Unseal Key", 3)
	if err != nil {
		zap.L().Error("Failed to read unseal keys", zap.Error(err))
		return api.InitResponse{}, fmt.Errorf("failed to prompt for unseal keys: %w", err)
	}

	root, err := interaction.PromptSecrets("Root Token", 1)
	if err != nil {
		zap.L().Error("Failed to read root token", zap.Error(err))
		return api.InitResponse{}, fmt.Errorf("failed to prompt for root token: %w", err)
	}

	return api.InitResponse{
		KeysB64:   keys,
		RootToken: root[0],
	}, nil
}

// UserSecretPath returns the Vault KV path for a user's secret material.
// NOTE: Do not log paths directly if they may include sensitive usernames.
func UserSecretPath(username string) string {
	path := fmt.Sprintf("users/%s", username)
	zap.L().Debug("Resolved user secret Vault path", zap.String("username", username), zap.String("path", path))
	return path
}

// GetVaultHealthEndpoint constructs the Vault health check URL based on the configured listener address.
// It defaults to localhost if no explicit environment address is provided.
func GetVaultHealthEndpoint() string {
	host := strings.Split(shared.ListenerAddr, ":")[0]
	endpoint := fmt.Sprintf("https://%s/v1/sys/health", host)
	zap.L().Debug("Resolved Vault health endpoint", zap.String("endpoint", endpoint))
	return endpoint
}

// PrepareVaultDirsAndConfig returns the config dir, config file path, and Vault address,
// and ensures necessary directories are created. Returns an error if critical preparation fails.
func PrepareVaultDirsAndConfig(distro string) (string, string, string, error) {
	var configDir string
	switch distro {
	case "debian", "rhel":
		configDir = shared.VaultConfigDirDebian
	default:
		configDir = shared.VaultConfigDirDebian
	}

	if err := os.MkdirAll(configDir, shared.DirPermStandard); err != nil {
		zap.L().Warn("Failed to create Vault config dir", zap.String("path", configDir), zap.Error(err))
		return "", "", "", fmt.Errorf("create config dir: %w", err)
	}
	if err := os.MkdirAll(shared.VaultDataPath, shared.DirPermStandard); err != nil {
		zap.L().Warn("Failed to create Vault data dir", zap.String("path", shared.VaultDataPath), zap.Error(err))
		return "", "", "", fmt.Errorf("create data dir: %w", err)
	}

	configFile := filepath.Join(configDir, shared.DefaultConfigFilename)
	vaultAddr := shared.GetVaultAddr()

	return configDir, configFile, vaultAddr, nil
}

// PhaseEnsureClientHealthy makes sure we can reach a healthy Vault
// instance, and if not, attempts init / unseal flows automatically.
func PhaseEnsureClientHealthy() error {
	zap.L().Info("[4/6] Ensuring Vault client is available and healthy")

	//--------------------------------------------------------------------
	// 0. Fast‑path: is something already listening on 8179 as eos/vault?
	//--------------------------------------------------------------------
	if out, _ := exec.Command("sudo", "lsof", "-i", shared.VaultDefaultPort).Output(); len(out) > 0 {
		zap.L().Info("📡 Detected process on port 8179",
			zap.String("output", string(out)))

		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "vault") && strings.Contains(line, shared.EosUser) {
				zap.L().Info("✅ Vault already running as 'eos' – skipping health loop")
				return nil
			}
		}
		zap.L().Info("ℹ️ Port 8179 is in use (but not vault:eos) – continuing with SDK check")
	}

	//--------------------------------------------------------------------
	// 1.  Sanity: VAULT_ADDR and binary
	//--------------------------------------------------------------------
	if _, err := EnsureVaultEnv(); err != nil {
		return fmt.Errorf("could not determine Vault address: %w", err)
	}
	if _, err := exec.LookPath("vault"); err != nil {
		return fmt.Errorf("vault binary not installed or not in $PATH")
	}

	//--------------------------------------------------------------------
	// 2.  Health‑check / bootstrap loop (max 5 attempts)
	//--------------------------------------------------------------------
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	for attempt := 1; attempt <= 5; attempt++ {
		zap.L().Info("🔁 Vault health probe",
			zap.Int("attempt", attempt))

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		resp, err := client.Sys().HealthWithContext(ctx)
		cancel() // no defer inside the loop

		if err != nil {
			zap.L().Warn("🔌 Health request failed – retrying",
				zap.Error(err))
			time.Sleep(shared.VaultRetryDelay)
			continue
		}

		switch {
		case resp.Initialized && !resp.Sealed && !resp.Standby: // healthy & unsealed
			zap.L().Info("✅ Vault is initialised and unsealed",
				zap.String("version", resp.Version))
			return nil

		case !resp.Initialized: // not initialised
			zap.L().Info("ℹ️ Vault reports uninitialised (501) – running init flow")
			if err := initAndUnseal(client); err != nil {
				return fmt.Errorf("init/unseal failed: %w", err)
			}
			return nil

		case resp.Initialized && resp.Sealed:
			zap.L().Info("🔒 Vault reports sealed (503) – attempting auto‑unseal")
			if err := MustUnseal(client); err != nil {
				zap.L().Error("❌ Auto-unseal failed", zap.Error(err))
				return fmt.Errorf("auto-unseal failed: %w", err)
			}
			// Verify unseal succeeded
			status, err := client.Sys().SealStatus()
			if err != nil {
				return fmt.Errorf("post-unseal status check failed: %w", err)
			}
			if status.Sealed {
				return fmt.Errorf("vault still sealed after unseal attempt")
			}
			zap.L().Info("✅ Vault successfully unsealed via fallback")
			return nil

		case resp.Standby: // standby
			zap.L().Info("🟡 Vault is in standby – treating as healthy for CLI")
			return nil

		default:
			zap.L().Warn("⚠️ Unexpected health state",
				zap.Any("response", resp))
			time.Sleep(shared.VaultRetryDelay)
			return err
		}
	}
	return fmt.Errorf("vault not healthy after multiple attempts")
}

func EnsureVaultAuthEnabled(client *api.Client, method, path string) error {
	existing, err := client.Sys().ListAuth()
	if err != nil {
		return err
	}
	if _, ok := existing[path]; ok {
		return nil
	}
	return client.Sys().EnableAuthWithOptions(strings.TrimSuffix(path, "/"), &api.EnableAuthOptions{Type: method})
}

func EnsureVaultAuthMethods(client *api.Client) error {
	if err := EnsureAuthMethod(client, "userpass", "userpass/"); err != nil {
		return err
	}
	if err := EnsureAuthMethod(client, "approle", "approle/"); err != nil {
		return err
	}
	return nil
}

func EnsureAuthMethod(client *api.Client, methodType, mountPath string) error {
	existing, err := client.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("failed to list Vault auth methods: %w", err)
	}

	if _, ok := existing[mountPath]; ok {
		return nil // Already enabled
	}

	return client.Sys().EnableAuthWithOptions(
		strings.TrimSuffix(mountPath, "/"),
		&api.EnableAuthOptions{Type: methodType},
	)
}
