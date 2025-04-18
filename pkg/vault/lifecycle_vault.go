// pkg/vault/vault_lifecycle.go

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//
// ========================== CREATE ==========================
//

func EnsureVault(kvPath string, kvData map[string]string, log *zap.Logger) error {
	log.Info("🔐 Vault setup starting")

	if err := phaseInstallVault(log); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if err := phasePatchVaultConfigIfNeeded(log); err != nil {
		return fmt.Errorf("patch-config: %w", err)
	}
	if err := phaseEnsureVaultRuntimeDir(log); err != nil {
		return fmt.Errorf("runtime-dir: %w", err)
	}
	if err := phaseEnsureClientHealthy(log); err != nil {
		return fmt.Errorf("client-health: %w", err)
	}
	client, err := phaseInitAndUnsealVault(log)
	if err != nil {
		return fmt.Errorf("init-unseal: %w", err)
	}
	if err := phaseApplyCoreSecrets(client, kvPath, kvData, log); err != nil {
		return fmt.Errorf("apply-secrets: %w", err)
	}
	log.Info("✅ Vault setup complete")
	return nil
}

// phaseInstallVault ensures Vault is installed using the appropriate package manager.
func phaseInstallVault(log *zap.Logger) error {
	log.Info("[1/6] Ensuring Vault is installed")

	distro := platform.DetectLinuxDistro(log)
	log.Info("Detected Linux distribution", zap.String("distro", distro))

	switch distro {
	case "debian":
		log.Info("Using APT to install Vault", zap.String("installer", "apt-get"))
		if err := InstallVaultViaApt(log); err != nil {
			log.Error("❌ Vault installation via APT failed", zap.Error(err))
			return fmt.Errorf("vault install via apt failed: %w", err)
		}
	case "rhel":
		log.Info("Using DNF to install Vault", zap.String("installer", "dnf"))
		if err := InstallVaultViaDnf(log); err != nil {
			log.Error("❌ Vault installation via DNF failed", zap.Error(err))
			return fmt.Errorf("vault install via dnf failed: %w", err)
		}
	default:
		log.Error("❌ Unsupported Linux distro for Vault install", zap.String("distro", distro))
		return fmt.Errorf("unsupported distro for Vault install: %s", distro)
	}

	log.Info("✅ Vault installed successfully")
	return nil
}

// phasePatchVaultConfigIfNeeded ensures Vault is configured to use the expected port (8179).
func phasePatchVaultConfigIfNeeded(log *zap.Logger) error {
	log.Info("[2/6] Checking for Vault port mismatch (8200 → 8179)")

	data, err := os.ReadFile(VaultConfigPath)
	if err != nil {
		log.Warn("Could not read Vault config file", zap.String("path", VaultConfigPath), zap.Error(err))
		return nil // Not fatal, just warn
	}
	content := string(data)

	// Skip if already using the correct port
	if strings.Contains(content, "8179") {
		log.Info("✅ Vault config already uses port 8179 — no patch needed")
		return nil
	}

	// Replace 8200 with 8179
	if strings.Contains(content, "8200") {
		log.Warn("🔧 Vault config uses port 8200 — patching to 8179")
		newContent := strings.ReplaceAll(content, "8200", "8179")
		if err := os.WriteFile(VaultConfigPath, []byte(newContent), 0644); err != nil {
			return fmt.Errorf("failed to write patched Vault config: %w", err)
		}

		// Restart Vault service to apply change
		log.Info("🔁 Restarting Vault service to apply config changes...")
		cmd := exec.Command("systemctl", "restart", "vault")
		if err := cmd.Run(); err != nil {
			log.Error("❌ Failed to restart Vault service", zap.Error(err))
			return fmt.Errorf("vault restart failed after patch: %w", err)
		}

		log.Info("✅ Vault config patched and service restarted successfully")
		return nil
	}

	log.Info("ℹ️ No 8200 port found in Vault config — no changes applied")
	return nil
}

// phaseEnsureVaultRuntimeDir ensures the Vault runtime directory exists with secure permissions.
func phaseEnsureVaultRuntimeDir(log *zap.Logger) error {
	log.Info("[3/6] Ensuring Vault runtime directory exists")

	runtimeDir := EosRunDir // e.g., "/run/eos"

	// Create directory if missing
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		log.Error("❌ Failed to create Vault runtime directory", zap.String("path", runtimeDir), zap.Error(err))
		return fmt.Errorf("could not create Vault runtime dir: %w", err)
	}

	// Set strict permissions
	if err := os.Chmod(runtimeDir, 0700); err != nil {
		log.Warn("⚠️ Failed to enforce 0700 permissions on runtime dir", zap.Error(err))
	} else {
		log.Info("✅ Vault runtime directory ready", zap.String("path", runtimeDir))
	}

	return nil
}

func phaseEnsureClientHealthy(log *zap.Logger) error {
	log.Info("[4/6] Ensuring Vault client is available and healthy")

	// Detect if port is in use
	if output, err := exec.Command("ss", "-tuln").Output(); err == nil {
		if strings.Contains(string(output), ":8179") {
			log.Warn("⚠️ Port 8179 is already in use — assuming Vault may already be running", zap.String("hint", "check if another Vault or process is running"))
		}
	}

	// Ensure VAULT_ADDR is set
	if _, err := EnsureVaultAddr(log); err != nil {
		return fmt.Errorf("could not determine Vault address: %w", err)
	}

	// Check Vault binary
	if _, err := exec.LookPath("vault"); err != nil {
		return fmt.Errorf("vault binary not installed or not in PATH")
	}

	// Attempt to create client and ping Vault once
	log.Info("📡 Pinging Vault once to check health")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := NewClient(log)
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	health, err := client.Sys().HealthWithContext(ctx)
	if err != nil {
		log.Error("❌ Vault health check failed", zap.Error(err))
		log.Warn("💡 Tip: Check if Vault is already running or stuck in a bad state")
		log.Warn("💡 You can inspect logs with: journalctl -u vault -f")
		return fmt.Errorf("vault not responding: %w", err)
	}

	if health.Sealed {
		log.Warn("🔒 Vault is sealed", zap.String("version", health.Version))
	} else {
		log.Info("✅ Vault is unsealed and responding", zap.String("version", health.Version))
	}

	return nil
}
func phaseInitAndUnsealVault(log *zap.Logger) (*api.Client, error) {
	log.Info("[5/6] Initializing and unsealing Vault if necessary")

	// Create a fresh Vault client
	client, err := NewClient(log)
	if err != nil {
		return nil, fmt.Errorf("could not create Vault client: %w", err)
	}

	// Initialize Vault (or reuse fallback + unseal)
	initRes, err := client.Sys().Init(&api.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	})
	if err != nil {
		// Already initialized? Fallback to stored init result
		if IsAlreadyInitialized(err, log) {
			log.Info("✅ Vault already initialized — reusing stored init result")

			initRes, err := LoadInitResultOrPrompt(client, log)
			if err != nil {
				return nil, fmt.Errorf("vault is already initialized but fallback failed: %w", err)
			}
			if err := UnsealVault(client, initRes, log); err != nil {
				return nil, fmt.Errorf("failed to unseal vault: %w", err)
			}
			client.SetToken(initRes.RootToken)
			return client, nil
		}
		return nil, fmt.Errorf("vault init error: %w", err)
	}

	// 🆕 Vault has just been initialized
	log.Info("🎉 Vault initialized")
	if err := UnsealVault(client, initRes, log); err != nil {
		return nil, fmt.Errorf("failed to unseal new Vault: %w", err)
	}
	client.SetToken(initRes.RootToken)

	// Persist init result for later reuse
	if err := Write(client, "vault_init", initRes, log); err != nil {
		log.Warn("Could not persist Vault init result", zap.Error(err))
	} else {
		log.Info("💾 Vault init result persisted to Vault")
	}

	return client, nil
}

func phaseApplyCoreSecrets(client *api.Client, kvPath string, kvData map[string]string, log *zap.Logger) error {
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

func InstallVaultViaApt(log *zap.Logger) error {
	log.Info("🔍 Checking if Vault is already installed via apt")
	if _, err := exec.LookPath("vault"); err == nil {
		log.Info("✅ Vault is already installed")
		return nil
	}

	log.Info("📦 Vault binary not found, proceeding with installation via apt")

	// Step 1: Add the HashiCorp APT repo
	log.Info("➕ Adding HashiCorp APT repo")
	aptCmd := exec.Command("bash", "-c", `curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg && echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list`)
	aptCmd.Stdout = os.Stdout
	aptCmd.Stderr = os.Stderr
	if err := aptCmd.Run(); err != nil {
		return fmt.Errorf("failed to add APT repo: %w", err)
	}

	// Step 2: Refresh APT cache
	log.Info("♻️ Updating APT package cache")
	if err := exec.Command("apt-get", "update").Run(); err != nil {
		log.Warn("APT update failed", zap.Error(err))
	}

	// Step 3: Install Vault
	log.Info("📦 Installing Vault via apt")
	installCmd := exec.Command("apt-get", "install", "-y", "vault")
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("❌ Failed to install Vault via apt: %w", err)
	}

	log.Info("✅ Vault installed successfully via apt")
	return nil
}

func InstallVaultViaDnf(log *zap.Logger) error {
	log.Info("🔍 Checking if Vault is already installed via dnf")
	if _, err := exec.LookPath("vault"); err == nil {
		log.Info("✅ Vault is already installed")
		return nil
	}

	log.Info("📦 Vault binary not found, proceeding with installation via dnf")

	// Step 1: Ensure the repo exists
	repoFile := "/etc/yum.repos.d/hashicorp.repo"
	if _, err := os.Stat(repoFile); os.IsNotExist(err) {
		log.Info("➕ Adding HashiCorp YUM repo")
		repoContent := `[hashicorp]
name=HashiCorp Stable - $basearch
baseurl=https://rpm.releases.hashicorp.com/RHEL/9/$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://rpm.releases.hashicorp.com/gpg`
		if err := os.WriteFile(repoFile, []byte(repoContent), 0644); err != nil {
			return fmt.Errorf("failed to write YUM repo file: %w", err)
		}
	} else {
		log.Info("✅ HashiCorp YUM repo already present", zap.String("path", repoFile))
	}

	// Step 2: Refresh repo metadata
	log.Info("♻️ Cleaning and refreshing DNF cache")
	_ = exec.Command("dnf", "clean", "all").Run()
	_ = exec.Command("dnf", "makecache").Run()

	// Step 3: Install Vault
	log.Info("📦 Installing Vault via dnf")
	dnfCmd := exec.Command("dnf", "install", "-y", "vault")
	dnfCmd.Stdout = os.Stdout
	dnfCmd.Stderr = os.Stderr
	if err := dnfCmd.Run(); err != nil {
		return fmt.Errorf("❌ Failed to install Vault via dnf: %w", err)
	}

	log.Info("✅ Vault installed successfully via dnf")
	return nil
}

/* Initialize Vault (if not already initialized) */
func SetupVault(client *api.Client, log *zap.Logger) (*api.Client, *api.InitResponse, error) {
	fmt.Println("\nInitializing Vault...")

	if err := EnsureRuntimeDir(log); err != nil {
		log.Error("Runtime dir missing or invalid", zap.Error(err))
		return nil, nil, err
	}

	initRes, err := client.Sys().Init(&api.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	})
	if err != nil {
		if IsAlreadyInitialized(err, log) {
			fmt.Println("✅ Vault already initialized.")

			// ✨ Reuse fallback or prompt logic
			initRes, err := LoadInitResultOrPrompt(client, log)
			if err != nil {
				return nil, nil, fmt.Errorf("vault already initialized and fallback failed: %w\n💡 Run `eos enable vault` on a fresh Vault to reinitialize and regenerate fallback data", err)
			}

			// 🔓 Unseal and auth
			if err := UnsealVault(client, initRes, log); err != nil {
				return nil, nil, fmt.Errorf("failed to unseal already-initialized Vault: %w", err)
			}
			client.SetToken(initRes.RootToken)

			// ✅ Re-store init result
			if err := Write(client, "vault_init", initRes, log); err != nil {
				log.Warn("Failed to persist Vault init result", zap.Error(err))
			} else {
				fmt.Println("✅ Vault init result persisted successfully")
			}
			return client, initRes, nil
		}
		return nil, nil, fmt.Errorf("init failed: %w", err)
	}

	// 🆕 Vault just initialized: unseal and persist
	DumpInitResult(initRes, log)
	if err := UnsealVault(client, initRes, log); err != nil {
		return nil, nil, err
	}
	client.SetToken(initRes.RootToken)

	if err := Write(client, "vault_init", initRes, log); err != nil {
		return nil, nil, fmt.Errorf("failed to persist Vault init result: %w", err)
	}
	fmt.Println("✅ Vault init result persisted successfully")

	return client, initRes, nil
}

//
// ========================== LIST ==========================
//

// VaultList returns keys under a path
func ListVault(path string, log *zap.Logger) ([]string, error) {
	client, err := GetPrivilegedVaultClient(log)
	if err != nil {
		return nil, err
	}
	list, err := client.Logical().List("secret/metadata/" + path)
	if err != nil || list == nil {
		return nil, err
	}
	raw := list.Data["keys"].([]interface{})
	keys := make([]string, len(raw))
	for i, k := range raw {
		keys[i] = fmt.Sprintf("%v", k)
	}
	return keys, nil
}

// Helper: Marshal to Vault KV payload format
func toMap(v interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"json": string(data)}, nil
}

//
// ========================== READ ==========================
//

// VaultRead reads and decodes a secret struct from Vault
func ReadVault[T any](path string, log *zap.Logger) (*T, error) {
	client, err := GetPrivilegedVaultClient(log)
	if err != nil {
		return nil, err
	}
	kv := client.KVv2("secret")

	secret, err := kv.Get(context.Background(), path)
	if err != nil {
		return nil, err
	}
	raw, ok := secret.Data["json"].(string)
	if !ok {
		return nil, errors.New("missing or invalid 'json' field in secret")
	}
	var result T
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret JSON: %w", err)
	}
	return &result, nil
}

// readTokenFromSink reads the Vault Agent token (run as 'eos' system user)
func readTokenFromSink(path string) (string, error) {
	if path == "" {
		path = VaultAgentTokenPath
	}
	out, err := exec.Command("sudo", "-u", "eos", "cat", path).Output()
	if err != nil {
		return "", fmt.Errorf("failed to read token from Vault Agent sink at %s: %w", path, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// GetPrivilegedVaultClient returns a Vault client authenticated as 'eos' system user
func GetPrivilegedVaultClient(log *zap.Logger) (*api.Client, error) {
	token, err := readTokenFromSink(VaultAgentTokenPath)
	if err != nil {
		return nil, err
	}
	client, err := NewClient(log)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	return client, nil
}

//
// ========================== UPDATE ==========================
//

func TryPatchVaultPortIfNeeded(log *zap.Logger) {
	b, err := os.ReadFile(VaultConfigPath)
	if err != nil {
		log.Warn("Could not read Vault config file", zap.String("path", VaultConfigPath), zap.Error(err))
		return
	}
	content := string(b)

	// Bail if already using 8179
	if strings.Contains(content, "8179") {
		log.Info("Vault config already uses port 8179 — no need to patch")
		return
	}

	// Check if 8200 is hardcoded and replace
	if strings.Contains(content, "8200") {
		newContent := strings.ReplaceAll(content, "8200", "8179")
		if err := os.WriteFile(VaultConfigPath, []byte(newContent), 0644); err != nil {
			log.Error("Failed to patch Vault config file", zap.Error(err))
			return
		}
		log.Info("✅ Vault port patched from 8200 → 8179 in config")

		// Restart Vault
		log.Info("🔁 Restarting Vault to apply new config...")
		cmd := exec.Command("systemctl", "restart", "vault")
		if err := cmd.Run(); err != nil {
			log.Error("❌ Failed to restart Vault after patching", zap.Error(err))
			return
		}
		log.Info("✅ Vault restarted successfully")
	} else {
		log.Info("No 8200 binding found in config — nothing to patch")
	}
}

//
// ========================== DELETE ==========================
//

// Purge removes Vault repo artifacts and paths based on the Linux distro.
// It returns a list of removed files and a map of errors keyed by path.
func Purge(distro string, log *zap.Logger) (removed []string, errs map[string]error) {
	errs = make(map[string]error)

	log.Info("🧹 Starting full Vault purge sequence", zap.String("distro", distro))

	// 1. Expand and remove all purge paths (supports wildcards like /etc/vault*)
	log.Info("🔍 Purging Vault runtime, config, and data directories...")
	seen := make(map[string]bool)

	for _, pattern := range VaultPurgePaths {
		expanded, _ := filepath.Glob(pattern)
		if len(expanded) == 0 {
			expanded = []string{pattern} // fallback
		}
		for _, actual := range expanded {
			if seen[actual] {
				continue // avoid duplicates
			}
			seen[actual] = true

			if err := os.RemoveAll(actual); err != nil && !os.IsNotExist(err) {
				log.Error("❌ Failed to remove purge path", zap.String("path", actual), zap.Error(err))
				errs[actual] = err
			} else {
				log.Info("✅ Removed purge path", zap.String("path", actual))
				removed = append(removed, actual)
			}
		}
	}

	// 2. Distro-specific package manager cleanup
	switch distro {
	case "debian":
		log.Info("🔧 Removing APT keyring and source list")
		for _, path := range []string{AptKeyringPath, AptListPath} {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				log.Error("❌ Failed to remove APT file", zap.String("path", path), zap.Error(err))
				errs[path] = fmt.Errorf("failed to remove %s: %w", path, err)
			} else {
				log.Info("✅ Removed APT file", zap.String("path", path))
				removed = append(removed, path)
			}
		}
	case "rhel":
		log.Info("🔧 Removing DNF repo file", zap.String("path", DnfRepoFilePath))
		if err := os.Remove(DnfRepoFilePath); err != nil && !os.IsNotExist(err) {
			log.Error("❌ Failed to remove DNF repo file", zap.String("path", DnfRepoFilePath), zap.Error(err))
			errs[DnfRepoFilePath] = fmt.Errorf("failed to remove %s: %w", DnfRepoFilePath, err)
		} else {
			log.Info("✅ Removed DNF repo file", zap.String("path", DnfRepoFilePath))
			removed = append(removed, DnfRepoFilePath)
		}
	default:
		log.Warn("⚠️ No package manager cleanup defined for distro", zap.String("distro", distro))
	}

	// 3. Optional binary cleanup
	log.Info("🗑️ Attempting to remove Vault binary", zap.String("path", binaryPath))
	if err := os.Remove(binaryPath); err != nil && !os.IsNotExist(err) {
		log.Error("❌ Failed to remove Vault binary", zap.String("path", binaryPath), zap.Error(err))
		errs[binaryPath] = fmt.Errorf("failed to remove %s: %w", binaryPath, err)
	} else {
		log.Info("✅ Removed Vault binary", zap.String("path", binaryPath))
		removed = append(removed, binaryPath)
	}

	// 4. Reload systemd to clean up any dangling service definitions
	log.Info("🔁 Reloading systemd daemon to unregister removed Vault services...")
	_ = exec.Command("systemctl", "daemon-reexec").Run()
	_ = exec.Command("systemctl", "daemon-reload").Run()

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
