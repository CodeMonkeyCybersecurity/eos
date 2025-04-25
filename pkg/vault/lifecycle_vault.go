// pkg/vault/vault_lifecycle.go

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

func EnsureVault(kvPath string, kvData map[string]string, log *zap.Logger) (*api.Client, error) {
	log.Info("🔐 Vault setup starting")

	log.Info("[1/11] Generating Vault TLS Certificate")
	if err := GenerateVaultTLSCert(log); err != nil {
		log.Error("❌ Failed to generate Vault TLS Certificate", zap.Error(err))
		return nil, fmt.Errorf("tls-gen: %w", err)
	}
	log.Info("✅ TLS Certificate generated")

	log.Info("[2/11] Trusting self-signed CA system-wide")
	if err := TrustVaultCA(log); err != nil {
		log.Error("❌ Failed to trust Vault CA", zap.Error(err))
		return nil, err
	}
	log.Info("✅ Vault CA trusted")

	log.Info("[3/11] Installing Vault binaries and systemd service")
	if err := phaseInstallVault(log); err != nil {
		log.Error("❌ Vault installation failed", zap.Error(err))
		return nil, fmt.Errorf("install: %w", err)
	}
	log.Info("✅ Vault installed")

	log.Info("[4/11] Patching vault.hcl config if needed")
	if err := phasePatchVaultConfigIfNeeded(log); err != nil {
		log.Error("❌ Failed to patch Vault config", zap.Error(err))
		return nil, fmt.Errorf("patch-config: %w", err)
	}
	log.Info("✅ Vault config verified")

	log.Info("[5/11] Waiting for healthy Vault client")
	if err := phaseEnsureClientHealthy(log); err != nil {
		log.Error("❌ Vault client not healthy", zap.Error(err))
		return nil, fmt.Errorf("client-health: %w", err)
	}
	log.Info("✅ Vault client healthy")

	log.Info("[6/11] Initializing and unsealing Vault")
	client, err := NewClient(log)
	if err != nil {
		log.Error("❌ Failed to create Vault client", zap.Error(err))
		return nil, fmt.Errorf("create client: %w", err)
	}

	client, err = phaseInitAndUnsealVault(client, log)
	if err != nil {
		log.Error("❌ Failed to initialize/unseal Vault", zap.Error(err))
		return nil, fmt.Errorf("init-unseal: %w", err)
	}
	log.Info("✅ Vault initialized and unsealed")

	log.Info("[7/11] Enabling KV v2 at secrets mount")
	if err := EnsureKVv2Enabled(client, strings.TrimSuffix(shared.KVNamespaceSecrets, "/"), log); err != nil {
		log.Error("❌ Failed to enable KV v2", zap.Error(err))
		return nil, fmt.Errorf("kv-v2 enable failed: %w", err)
	}
	log.Info("✅ KV v2 enabled")

	log.Info("[8/11] Bootstrapping test secret")
	if err := BootstrapKV(client, "bootstrap/test", log); err != nil {
		log.Error("❌ Failed to bootstrap KV", zap.Error(err))
		return nil, fmt.Errorf("kv bootstrap failed: %w", err)
	}
	log.Info("✅ KV test secret bootstrapped")

	log.Info("[9/11] Writing Vault policies")
	if err := EnsurePolicy(client, log); err != nil {
		log.Error("❌ Failed to write policy", zap.Error(err))
		return nil, fmt.Errorf("policy write failed: %w", err)
	}
	log.Info("✅ Policy written")

	log.Info("[10/11] Configuring AppRole auth method")
	if err := EnsureAppRoleAuth(client, log); err != nil {
		log.Error("❌ Failed to configure AppRole", zap.Error(err))
		return nil, fmt.Errorf("approle setup failed: %w", err)
	}
	log.Info("✅ AppRole configured")

	log.Info("[11/11] Applying core secrets to Vault")
	if err := phaseApplyCoreSecrets(client, kvPath, kvData, log); err != nil {
		log.Error("❌ Failed to apply core secrets", zap.Error(err))
		return nil, fmt.Errorf("apply-secrets: %w", err)
	}
	log.Info("✅ Core secrets applied")

	log.Info("🎉 Vault setup complete")
	return client, nil
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

	data, err := os.ReadFile(shared.VaultConfigPath)
	if err != nil {
		log.Warn("Could not read Vault config file", zap.String("path", shared.VaultConfigPath), zap.Error(err))
		return nil // Not fatal, just warn
	}
	content := string(data)

	// Skip if already using the correct port
	if strings.Contains(content, shared.VaultDefaultPort) {
		log.Info("✅ Vault config already uses port 8179 — no patch needed")
		return nil
	}

	// Replace 8200 with 8179
	if strings.Contains(content, "8200") {
		log.Warn("🔧 Vault config uses port 8200 — patching to 8179")
		newContent := strings.ReplaceAll(content, "8200", shared.VaultDefaultPort)
		if err := os.WriteFile(shared.VaultConfigPath, []byte(newContent), 0644); err != nil {
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

// phaseEnsureClientHealthy makes sure we can reach a healthy Vault
// instance, and if not, attempts init / unseal flows automatically.
func phaseEnsureClientHealthy(log *zap.Logger) error {
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
			time.Sleep(2 * time.Second)
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
			time.Sleep(2 * time.Second)
			return err
		}
	}
	return fmt.Errorf("vault not healthy after multiple attempts")
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

	// Step 1: Attempt initialization with timeout
	log.Debug("⏱️ Creating context for Vault init with 30s timeout")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Info("🧪 Attempting Vault initialization")
	initRes, err := client.Sys().InitWithContext(ctx, &api.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	})
	if err != nil {
		// Step 2: Handle already-initialized fallback
		if IsAlreadyInitialized(err, log) {
			log.Info("ℹ️ Vault already initialized — attempting reuse via fallback")

			initRes, err := LoadInitResultOrPrompt(client, log)
			if err != nil {
				log.Error("❌ Failed to reuse init result", zap.Error(err))
				log.Warn("💡 Run `eos enable vault` on a fresh Vault to regenerate fallback data")
				return nil, nil, fmt.Errorf("vault already initialized and fallback failed: %w", err)
			}

			log.Debug("🔓 Reusing init result — attempting unseal + persist")
			if err := finalizeVaultSetup(client, initRes, log); err != nil {
				log.Error("❌ Failed to finalize Vault setup from fallback", zap.Error(err))
				return nil, nil, fmt.Errorf("failed to finalize reused Vault setup: %w", err)
			}

			log.Info("✅ Vault setup finalized from fallback")
			return client, initRes, nil
		}

		// Unknown error: surface context-related issues clearly
		log.Error("❌ Vault initialization failed", zap.Error(err))
		if errors.Is(err, context.DeadlineExceeded) {
			log.Warn("💡 Vault init timed out — is the Vault API responding on the correct port?")
		} else if strings.Contains(err.Error(), "connection refused") {
			log.Warn("💡 Vault appears down — check systemd status or port binding")
		}
		return nil, nil, fmt.Errorf("vault init error: %w", err)
	}

	// Step 3: Successful init
	log.Info("🎉 Vault successfully initialized")

	if len(initRes.Keys) == 0 || initRes.RootToken == "" {
		log.Error("❌ Init result missing unseal keys or root token")
		return nil, nil, fmt.Errorf("invalid init result returned by Vault")
	}

	if err := finalizeVaultSetup(client, initRes, log); err != nil {
		log.Error("❌ Final Vault setup failed", zap.Error(err))
		return nil, nil, fmt.Errorf("vault finalize setup error: %w", err)
	}

	log.Info("✅ Vault setup completed and ready")
	log.Info("📁 Vault unseal keys and root token stored to fallback file and Vault KV")
	return client, initRes, nil
}

func PrepareVaultAgentEnvironment(log *zap.Logger) error {
	// existing: create /run/eos
	if err := os.MkdirAll(shared.EosRunDir, shared.FilePermOwnerRWX); err != nil {
		log.Error("Failed to create run directory", zap.String("path", shared.EosRunDir), zap.Error(err))
		return err
	}
	log.Info("Ensured run directory", zap.String("path", shared.EosRunDir))

	// NEW: create /var/lib/eos/secrets
	if err := os.MkdirAll(shared.SecretsDir, shared.FilePermOwnerRWX); err != nil {
		log.Error("Failed to create secrets directory", zap.String("path", shared.SecretsDir), zap.Error(err))
		return err
	}
	log.Info("Ensured secrets directory", zap.String("path", shared.SecretsDir))
	return nil
}

func finalizeVaultSetup(client *api.Client, initRes *api.InitResponse, log *zap.Logger) error {
	log.Info("🔐 Finalizing Vault setup")

	// Step 0: Defensive validation of initRes
	if len(initRes.Keys) == 0 || initRes.RootToken == "" {
		log.Error("❌ Invalid init result: missing keys or root token")
		return fmt.Errorf("invalid init result: missing keys or token")
	}

	// Step 1: Attempt unseal
	log.Debug("🔓 Attempting to unseal Vault using init result")
	if err := UnsealVault(client, initRes, log); err != nil {
		log.Error("❌ Failed to unseal Vault", zap.Error(err))
		log.Warn("💡 Make sure Vault is running and the unseal keys are correct")
		return fmt.Errorf("failed to unseal vault: %w", err)
	}
	log.Info("✅ Vault unsealed successfully")

	// (Optional) Verify unseal status
	sealStatus, err := client.Sys().SealStatus()
	if err != nil {
		log.Warn("⚠️ Failed to verify seal status after unsealing", zap.Error(err))
	} else if sealStatus.Sealed {
		log.Error("❌ Vault reports still sealed after unseal attempt")
		return fmt.Errorf("vault still sealed after unseal")
	}

	// Step 2: Set root token
	log.Debug("🔑 Setting root token on Vault client")
	client.SetToken(initRes.RootToken)

	// Step 3: Write init result for future reuse
	log.Debug("💾 Persisting Vault init result")
	if err := Write(client, "vault_init", initRes, log); err != nil {
		log.Error("❌ Failed to persist Vault init result", zap.Error(err))
		log.Warn("💡 This will require re-unsealing on next run if not stored")
		return fmt.Errorf("failed to persist init result: %w", err)
	}

	log.Info("📦 Vault init result written to Vault backend or fallback")
	return nil
}

func TryPatchVaultPortIfNeeded(log *zap.Logger) {
	b, err := os.ReadFile(shared.VaultConfigPath)
	if err != nil {
		log.Warn("Could not read Vault config file", zap.String("path", shared.VaultConfigPath), zap.Error(err))
		return
	}
	content := string(b)

	// Bail if already using 8179
	if strings.Contains(content, shared.VaultDefaultPort) {
		log.Info("Vault config already uses port 8179 — no need to patch")
		return
	}

	// Check if 8200 is hardcoded and replace
	if strings.Contains(content, "8200") {
		newContent := strings.ReplaceAll(content, "8200", shared.VaultDefaultPort)
		if err := os.WriteFile(shared.VaultConfigPath, []byte(newContent), 0644); err != nil {
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

// Purge removes Vault repo artifacts and paths based on the Linux distro.
// It returns a list of removed files and a map of errors keyed by path.
func Purge(distro string, log *zap.Logger) (removed []string, errs map[string]error) {
	errs = make(map[string]error)

	log.Info("🧹 Starting full Vault purge sequence", zap.String("distro", distro))

	// 2. Distro-specific package manager cleanup
	switch distro {
	case "debian":
		log.Info("🔧 Removing APT keyring and source list")
		for _, path := range []string{shared.AptKeyringPath, shared.AptListPath} {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				log.Error("❌ Failed to remove APT file", zap.String("path", path), zap.Error(err))
				errs[path] = fmt.Errorf("failed to remove %s: %w", path, err)
			} else {
				log.Info("✅ Removed APT file", zap.String("path", path))
				removed = append(removed, path)
			}
		}
	case "rhel":
		log.Info("🔧 Removing DNF repo file", zap.String("path", shared.DnfRepoFilePath))
		if err := os.Remove(shared.DnfRepoFilePath); err != nil && !os.IsNotExist(err) {
			log.Error("❌ Failed to remove DNF repo file", zap.String("path", shared.DnfRepoFilePath), zap.Error(err))
			errs[shared.DnfRepoFilePath] = fmt.Errorf("failed to remove %s: %w", shared.DnfRepoFilePath, err)
		} else {
			log.Info("✅ Removed DNF repo file", zap.String("path", shared.DnfRepoFilePath))
			removed = append(removed, shared.DnfRepoFilePath)
		}
	default:
		log.Warn("⚠️ No package manager cleanup defined for distro", zap.String("distro", distro))
	}

	// 3. Optional binary cleanup
	log.Info("🗑️ Attempting to remove Vault binary", zap.String("path", shared.VaultBinaryPath))
	if err := os.Remove(shared.VaultBinaryPath); err != nil && !os.IsNotExist(err) {
		log.Error("❌ Failed to remove Vault binary", zap.String("path", shared.VaultBinaryPath), zap.Error(err))
		errs[shared.VaultBinaryPath] = fmt.Errorf("failed to remove %s: %w", shared.VaultBinaryPath, err)
	} else {
		log.Info("✅ Removed Vault binary", zap.String("path", shared.VaultBinaryPath))
		removed = append(removed, shared.VaultBinaryPath)
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

//
// ========================== LIFECYCLE_VAULT ==========================
//

/**/
// ✅ This ensures that **every elevation boundary is explicit and auditable**, and EOS remains thin and Unix-idiomatic.
// ---
// ### Decision: vault.hcl Configuration
// - **Port**: Use `8179` as the Vault listener port.
//   - Reason: Avoid conflicts with default `8200`, fits into a prime-number port scheme.
// - **Listener Address**: Bind to `0.0.0.0`, but firewall access by default.
//   - Allows LAN/local trust zone use while maintaining sensible defaults.
// - **Storage Backend**: Use file backend, stored under `/opt/pandora/data` (EOS Vault home).
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
//     - Falls back to 127.0.0.1:8179
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
// Agent creation logic now called after phaseApplycoreSecrets is this appropriate??
// ---

/**/
// TODO: RenderVaultServiceUnit() ([]byte, error)
/**/

/**/
// vault-agent-eos.service // should use `After=vault.service` and `Requires=vault.service`
// - This ensures the Vault service is active before the agent attempts to fetch a token.
/**/

func StartVaultService(log *zap.Logger) error {
	if err := WriteSystemdUnit(log); err != nil {
		return err
	}
	return ReloadDaemonAndEnable(log, "vault.service")
}
