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
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
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

	runtimeDir := EosRunDir

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

	// Check for any process on 8179
	output, err := exec.Command("lsof", "-i", ":8179").Output()
	if err == nil && len(output) > 0 {
		log.Info("📡 Detected process on port 8179", zap.String("output", string(output)))

		// Check if it's Vault running as eos
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "vault") && strings.Contains(line, "eos") {
				log.Info("✅ Detected Vault already running as 'eos' on port 8179 — skipping health check")
				return nil
			}
		}

		log.Info("ℹ️ Port 8179 in use but not by Vault/eos — continuing with health check")
	}

	// Vault address sanity check
	if _, err := EnsureVaultAddr(log); err != nil {
		return fmt.Errorf("could not determine Vault address: %w", err)
	}

	// Check if Vault binary exists
	if _, err := exec.LookPath("vault"); err != nil {
		return fmt.Errorf("vault binary not installed or not in PATH")
	}

	// Try to ping the Vault health endpoint via SDK
	client, err := NewClient(log)
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	log.Info("📡 Pinging Vault health endpoint")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	health, err := client.Sys().HealthWithContext(ctx)
	if err != nil {
		log.Error("❌ Vault health check failed", zap.Error(err))
		log.Warn("💡 Tip: Vault may not be running or is stuck")
		return fmt.Errorf("vault not responding: %w", err)
	}

	log.Info("✅ Vault responded", zap.Any("health", health))
	if health.Sealed {
		log.Info("🔒 Vault is sealed", zap.String("version", health.Version))
	}

	return nil
}

func phaseInitAndUnsealVault(log *zap.Logger) (*api.Client, error) {
	log.Info("[5/6] Initializing and unsealing Vault if necessary")

	// Step 1: Ensure directory structure is ready
	log.Debug("🔍 Verifying required Vault directories...")
	if err := EnsureVaultDirs(log); err != nil {
		log.Error("❌ Vault directory setup failed", zap.Error(err))
		return nil, fmt.Errorf("vault directory setup failed: %w", err)
	}

	// Step 2: Create Vault client
	log.Debug("🧪 Attempting to create Vault API client...")
	client, err := NewClient(log)
	if err != nil {
		log.Error("❌ Could not create Vault client", zap.Error(err))
		return nil, fmt.Errorf("could not create Vault client: %w", err)
	}
	log.Info("✅ Vault client created successfully", zap.String("address", client.Address()))

	// Step 3: Attempt initialization or reuse
	log.Debug("⚙️ Checking Vault initialization status...")
	client, _, err = SetupVault(client, log)
	if err != nil {
		log.Error("❌ Vault initialization or reuse failed", zap.Error(err))
		return nil, fmt.Errorf("vault init/unseal failed: %w", err)
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

func SetupVault(client *api.Client, log *zap.Logger) (*api.Client, *api.InitResponse, error) {
	log.Info("⚙️ Starting Vault setup")

	// Step 1: Ensure required directories exist
	if err := EnsureVaultDirs(log); err != nil {
		log.Error("❌ Vault directory setup failed", zap.Error(err))
		return nil, nil, err
	}

	// Step 2: Attempt initialization (with 10s timeout)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	initReq := &api.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	}

	log.Info("🧪 Attempting Vault initialization")
	initRes, err := client.Sys().InitWithContext(ctx, initReq)
	if err != nil {
		if IsAlreadyInitialized(err, log) {
			log.Info("ℹ️ Vault already initialized — attempting reuse")

			initRes, err := LoadInitResultOrPrompt(client, log)
			if err != nil {
				log.Error("❌ Failed to reuse init result", zap.Error(err))
				return nil, nil, fmt.Errorf("vault already initialized and fallback failed: %w", err)
			}

			if err := finalizeVaultSetup(client, initRes, log); err != nil {
				return nil, nil, err
			}

			return client, initRes, nil
		}

		log.Error("❌ Vault initialization failed", zap.Error(err))
		return nil, nil, fmt.Errorf("vault init error: %w", err)
	}

	// Step 3: New Vault instance — unseal and store
	log.Info("🎉 Vault successfully initialized")
	DumpInitResult(initRes, log)

	if err := finalizeVaultSetup(client, initRes, log); err != nil {
		return nil, nil, err
	}

	return client, initRes, nil
}

func EnsureVaultDirs(log *zap.Logger) error {
	dirs := []string{
		SecretsDir,
		EosRunDir,
	}

	uid, gid, err := system.LookupUser("eos")
	if err != nil {
		log.Warn("⚠️ Could not resolve eos UID/GID", zap.Error(err))
		uid, gid = 1001, 1001 // fallback, optionally make configurable
	}

	for _, dir := range dirs {
		log.Debug("🔧 Ensuring Vault dir", zap.String("path", dir))

		if err := os.MkdirAll(dir, 0750); err != nil {
			log.Error("❌ Failed to create Vault dir", zap.String("path", dir), zap.Error(err))
			return fmt.Errorf("failed to create dir %s: %w", dir, err)
		}

		info, err := os.Stat(dir)
		if err != nil {
			log.Warn("⚠️ Could not stat dir after creation", zap.String("path", dir), zap.Error(err))
			continue
		}

		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			if int(stat.Uid) != uid || int(stat.Gid) != gid {
				if err := os.Chown(dir, uid, gid); err != nil {
					log.Warn("⚠️ Could not chown Vault dir", zap.String("path", dir), zap.Error(err))
				} else {
					log.Info("🔐 Ownership updated", zap.String("path", dir), zap.Int("uid", uid), zap.Int("gid", gid))
				}
			}
		}
	}

	return nil
}

func finalizeVaultSetup(client *api.Client, initRes *api.InitResponse, log *zap.Logger) error {
	if err := UnsealVault(client, initRes, log); err != nil {
		log.Error("❌ Failed to unseal Vault", zap.Error(err))
		return fmt.Errorf("failed to unseal vault: %w", err)
	}

	client.SetToken(initRes.RootToken)

	if err := Write(client, "vault_init", initRes, log); err != nil {
		log.Warn("⚠️ Failed to persist Vault init result", zap.Error(err))
	} else {
		log.Info("💾 Vault init result persisted")
	}

	return nil
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
