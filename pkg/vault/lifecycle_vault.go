// pkg/vault/vault_lifecycle.go

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// PhaseInstallVault ensures Vault binary is installed via APT or DNF,
// depending on detected Linux distribution. No-op if already installed.
func PhaseInstallVault(log *zap.Logger) error {
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

// PhasePatchVaultConfigIfNeeded ensures Vault is configured to use the expected port (8179).
func PhasePatchVaultConfigIfNeeded(log *zap.Logger) error {
	log.Info("[2/6] Checking for Vault port mismatch (8200 → 8179)")

	data, err := os.ReadFile(shared.VaultConfigPath)
	if err != nil {
		log.Warn("Could not read Vault config file", zap.String("path", shared.VaultConfigPath), zap.Error(err))
		return nil // Not fatal, continue without patching
	}
	content := string(data)

	if strings.Contains(content, shared.VaultDefaultPort) {
		log.Info("✅ Vault config already uses port 8179 — no patch needed")
		return nil
	}

	if !strings.Contains(content, "8200") {
		log.Info("ℹ️ No 8200 port found in Vault config — no changes applied")
		return nil
	}

	// Patch config: replace 8200 with 8179
	log.Warn("🔧 Vault config uses port 8200 — patching to 8179")
	newContent := strings.ReplaceAll(content, "8200", shared.VaultDefaultPort)
	if err := os.WriteFile(shared.VaultConfigPath, []byte(newContent), 0644); err != nil {
		log.Error("❌ Failed to write patched Vault config", zap.Error(err))
		return fmt.Errorf("failed to write patched Vault config: %w", err)
	}

	log.Info("✅ Vault config patched successfully — restarting Vault service...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "restart", "vault")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Error("❌ Failed to restart Vault service after patch", zap.Error(err))
		return fmt.Errorf("vault restart failed after config patch: %w", err)
	}

	log.Info("✅ Vault service restarted successfully after config patch")
	return nil
}

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

// InstallVaultViaApt ensures the Vault binary is installed on Debian-based systems via APT.
// It adds the official HashiCorp repository if needed, installs Vault, and verifies the binary path.
func InstallVaultViaApt(log *zap.Logger) error {
	log.Info("🔍 Checking if Vault is already installed via apt")
	if _, err := exec.LookPath("vault"); err == nil {
		log.Info("✅ Vault is already installed")
		return nil
	}

	log.Info("📦 Vault binary not found, proceeding with installation via apt")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Step 1: Download and save the HashiCorp GPG key
	log.Info("➕ Downloading HashiCorp GPG key")
	curlCmd := exec.CommandContext(ctx, "curl", "-fsSL", "https://apt.releases.hashicorp.com/gpg")
	gpgCmd := exec.CommandContext(ctx, "gpg", "--dearmor", "-o", "/usr/share/keyrings/hashicorp-archive-keyring.gpg")

	pipeReader, pipeWriter := io.Pipe()
	curlCmd.Stdout = pipeWriter
	gpgCmd.Stdin = pipeReader

	curlCmd.Stderr = os.Stderr
	gpgCmd.Stdout = os.Stdout
	gpgCmd.Stderr = os.Stderr

	if err := curlCmd.Start(); err != nil {
		return fmt.Errorf("failed to start curl: %w", err)
	}
	if err := gpgCmd.Start(); err != nil {
		return fmt.Errorf("failed to start gpg: %w", err)
	}

	if err := curlCmd.Wait(); err != nil {
		return fmt.Errorf("curl command failed: %w", err)
	}
	pipeWriter.Close()

	if err := gpgCmd.Wait(); err != nil {
		return fmt.Errorf("gpg command failed: %w", err)
	}

	// Step 2: Write the APT source list
	log.Info("➕ Adding HashiCorp APT repository")
	distroCodenameCmd := exec.CommandContext(ctx, "lsb_release", "-cs")
	codenameBytes, err := distroCodenameCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to detect distro codename: %w", err)
	}
	codename := strings.TrimSpace(string(codenameBytes))

	repoEntry := fmt.Sprintf(
		"deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com %s main\n",
		codename)

	if err := os.WriteFile("/etc/apt/sources.list.d/hashicorp.list", []byte(repoEntry), 0644); err != nil {
		return fmt.Errorf("failed to write APT source file: %w", err)
	}

	// Step 3: Update and install
	log.Info("♻️ Updating APT package cache")
	if err := exec.CommandContext(ctx, "apt-get", "update").Run(); err != nil {
		return fmt.Errorf("apt-get update failed: %w", err)
	}

	log.Info("📦 Installing Vault from HashiCorp repo via apt")
	installCmd := exec.CommandContext(ctx, "apt-get", "install", "-y", "vault")
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("vault installation via apt-get failed: %w", err)
	}

	vaultPath, err := exec.LookPath("vault")
	if err != nil {
		return fmt.Errorf("vault binary not found after install: %w", err)
	}
	log.Info("✅ Vault binary found", zap.String("path", vaultPath))
	return nil
}

func InstallVaultViaDnf(log *zap.Logger) error {
	log.Info("🔍 Checking if Vault is already installed via dnf")
	if _, err := exec.LookPath("vault"); err == nil {
		log.Info("✅ Vault is already installed")
		return nil
	}

	log.Info("📦 Vault binary not found, proceeding with installation via dnf")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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
	}

	log.Info("♻️ Cleaning and refreshing DNF cache")
	_ = exec.CommandContext(ctx, "dnf", "clean", "all").Run()
	_ = exec.CommandContext(ctx, "dnf", "makecache").Run()

	log.Info("📦 Installing Vault via dnf")
	dnfCmd := exec.CommandContext(ctx, "dnf", "install", "-y", "vault")
	dnfCmd.Stdout = os.Stdout
	dnfCmd.Stderr = os.Stderr
	if err := dnfCmd.Run(); err != nil {
		return fmt.Errorf("vault installation via dnf failed: %w", err)
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

// ValidateVaultConfig runs Vault's built-in configuration validation.
// It returns an error if validation fails, and logs the vault output for diagnosis.
// This must be called before attempting to start Vault.
func ValidateVaultConfig(log *zap.Logger) error {
	log.Info("🧪 Validating Vault configuration syntax")
	cmd := exec.Command("vault", "server", "-config", shared.VaultConfigPath, "-check")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("Vault config validation failed", zap.Error(err), zap.String("output", string(out)))
		return fmt.Errorf("vault config validation error: %w", err)
	}
	log.Info("✅ Vault config validation successful", zap.String("output", string(out)))
	return nil
}
