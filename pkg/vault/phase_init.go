// pkg/vault/lifecycle_init.go

package vault

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// PhaseInitAndUnsealVault is the entry point when Vault is uninitialized.
// It initializes Vault if necessary, confirms safe backup of init materials,
// unseals Vault, and stores a fallback copy of the init result.
func PhaseInitAndUnsealVault(client *api.Client, log *zap.Logger) (*api.Client, error) {
	log.Info("[5/6] Initializing and unsealing Vault if necessary")

	status, err := client.Sys().InitStatus()
	if err != nil {
		log.Error("❌ Failed to check Vault init status", zap.Error(err))
		return nil, err
	}
	if status {
		log.Info("🔓 Vault is already initialized — skipping")
		return client, nil
	}

	log.Info("⚙️ Vault not initialized — starting initialization sequence")
	initRes, err := InitVault(client, log)
	if err != nil {
		return nil, err
	}

	if err := PromptToSaveVaultInitData(initRes, log); err != nil {
		return nil, err
	}

	if err := ConfirmUnsealMaterialSaved(initRes, log); err != nil {
		return nil, err
	}

	if err := SaveInitResult(initRes, log); err != nil {
		return nil, err
	}

	if err := UnsealVault(client, initRes, log); err != nil {
		return nil, err
	}

	log.Info("✅ Vault initialization and unsealing complete")
	return client, nil
}

// initVault initializes Vault with default settings (5 keys, 3 threshold).
func InitVault(client *api.Client, log *zap.Logger) (*api.InitResponse, error) {
	initOptions := &api.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	}
	initRes, err := client.Sys().Init(initOptions)
	if err != nil {
		log.Error("❌ Vault initialization failed", zap.Error(err))
		return nil, err
	}
	log.Info("✅ Vault successfully initialized",
		zap.Int("num_keys", len(initRes.KeysB64)),
		zap.String("root_token_hash", crypto.HashString(initRes.RootToken)))
	return initRes, nil
}

// SaveInitResult stores the init result in fallback path.
func SaveInitResult(initRes *api.InitResponse, log *zap.Logger) error {
	b, err := json.MarshalIndent(initRes, "", "  ")
	if err != nil {
		log.Error("❌ Failed to marshal vault init result", zap.Error(err))
		return err
	}

	path := DiskPath("vault_init", log)
	if err := os.WriteFile(path, b, 0600); err != nil {
		log.Error("❌ Failed to write vault init file", zap.String("path", path), zap.Error(err))
		return err
	}

	log.Info("💾 Vault init result saved", zap.String("path", path))
	return nil
}

// LoadInitResultOrPrompt tries loading the init result from disk; otherwise prompts the user.
func LoadInitResultOrPrompt(client *api.Client, log *zap.Logger) (*api.InitResponse, error) {
	initRes := new(api.InitResponse)
	if err := ReadFallbackJSON(DiskPath("vault_init", log), initRes, log); err != nil {
		log.Warn("⚠️ Fallback file missing or unreadable — prompting user", zap.Error(err))
		return PromptForInitResult(log)
	}
	log.Info("✅ Vault init result loaded from fallback")
	return initRes, nil
}

func PromptToSaveVaultInitData(init *api.InitResponse, log *zap.Logger) error {
	fmt.Println("\n⚠️  WARNING: This is the only time you will see these unseal keys and root token.")
	fmt.Println("You MUST securely back them up. Losing them means permanent loss of access.")
	fmt.Print("\nType 'yes' to confirm you've saved the keys somewhere safe: ")

	var response string
	fmt.Scanln(&response)
	if strings.ToLower(strings.TrimSpace(response)) != "yes" {
		return fmt.Errorf("user did not confirm secure storage of unseal material")
	}

	log.Info("✅ User confirmed Vault init material has been backed up securely")
	return nil
}

func ConfirmUnsealMaterialSaved(init *api.InitResponse, log *zap.Logger) error {
	fmt.Println("\n🔐 Please re-enter 3 of your unseal keys and the root token to confirm you've saved them.")

	keys, err := crypto.PromptSecrets("Unseal Key", 3, log)
	if err != nil {
		return fmt.Errorf("failed to read unseal keys: %w", err)
	}
	root, err := crypto.PromptSecrets("Root Token", 1, log)
	if err != nil {
		return fmt.Errorf("failed to read root token: %w", err)
	}

	if crypto.HashString(root[0]) != crypto.HashString(init.RootToken) {
		return fmt.Errorf("root token did not match original")
	}

	matchCount := 0
	for _, entered := range keys {
		for _, known := range init.KeysB64 {
			if crypto.HashString(entered) == crypto.HashString(known) {
				matchCount++
				break
			}
		}
	}

	if matchCount < 3 {
		return fmt.Errorf("less than 3 unseal keys matched")
	}

	log.Info("✅ User successfully confirmed unseal material")
	return nil
}

func MaybeWriteVaultInitFallback(init *api.InitResponse, log *zap.Logger) error {
	fmt.Print("💾 Save Vault init material to fallback file? (y/N): ")
	var resp string
	fmt.Scanln(&resp)
	if strings.ToLower(resp) != "y" {
		log.Warn("❌ Skipping fallback write at user request")
		return nil
	}
	return SaveInitResult(init, log)
}

// initAndUnseal is called when /sys/health returns 501 (uninitialized).
func initAndUnseal(c *api.Client, log *zap.Logger) error {
	_, _, err := SetupVault(c, log)
	return err
}

// UnsealVault attempts to unseal Vault using either fallback file or interactive prompts.
func UnsealVault(client *api.Client, init *api.InitResponse, log *zap.Logger) error {
	// Submit 3 of 5 keys interactively
	log.Info("🔐 Submitting unseal keys to Vault")
	for i := 0; i < 3; i++ {
		resp, err := client.Sys().Unseal(init.KeysB64[i])
		if err != nil {
			return fmt.Errorf("failed to submit unseal key %d: %w", i+1, err)
		}
		log.Info("🔑 Unseal key accepted", zap.Int("submitted", i+1), zap.Bool("sealed", resp.Sealed))
		if !resp.Sealed {
			log.Info("✅ Vault is now unsealed")
			return nil
		}
	}
	return errors.New("vault remains sealed after submitting 3 unseal keys")
}

// TryLoadUnsealKeysFromFallback attempts to load the vault-init.json file and parse the keys.
func TryLoadUnsealKeysFromFallback(log *zap.Logger) (*api.InitResponse, error) {
	path := DiskPath("vault_init", log)
	log.Info("📂 Attempting fallback unseal using init file", zap.String("path", path))
	initRes := new(api.InitResponse)

	if err := ReadFallbackJSON(path, initRes, log); err != nil {
		log.Warn("⚠️ Failed to read fallback file", zap.Error(err))
		return nil, fmt.Errorf("failed to read vault init fallback file: %w", err)
	}
	if len(initRes.KeysB64) < 3 || initRes.RootToken == "" {
		return nil, fmt.Errorf("invalid or incomplete vault-init.json file")
	}
	log.Info("✅ Fallback file validated", zap.Int("keys_found", len(initRes.KeysB64)))
	return initRes, nil
}

// PromptUnsealKeys requests 3 unseal keys interactively with hidden input.
func PromptUnsealKeys(log *zap.Logger) ([]string, error) {
	log.Info("🔐 Please enter 3 base64-encoded unseal keys")
	return crypto.PromptSecrets("Unseal Key", 3, log)
}

// PromptRootToken requests the root token from the user.
func PromptRootToken(log *zap.Logger) (string, error) {
	log.Info("🔑 Please enter the Vault root token")
	tokens, err := crypto.PromptSecrets("Root Token", 1, log)
	if err != nil {
		return "", err
	}
	return tokens[0], nil
}

// ValidateRootToken checks if the root token is valid via a simple self-lookup.
func ValidateRootToken(client *api.Client, token string) error {
	client.SetToken(token)
	secret, err := client.Auth().Token().LookupSelf()
	if err != nil || secret == nil {
		return fmt.Errorf("token validation failed: %w", err)
	}
	return nil
}

// unsealFromStoredKeys is called when /sys/health returns 503 (sealed). We load the stored vault_init.json (or prompt) and unseal.
func unsealFromStoredKeys(c *api.Client, log *zap.Logger) error {
	initRes, err := LoadInitResultOrPrompt(c, log)
	if err != nil {
		return fmt.Errorf("could not load stored unseal keys: %w", err)
	}
	if err := UnsealVault(c, initRes, log); err != nil {
		return fmt.Errorf("auto‑unseal failed: %w", err)
	}
	// give the client a token so later calls work
	c.SetToken(initRes.RootToken)
	return nil
}

// ConfirmSecureStorage prompts user to re-enter keys to confirm they've been saved.
func ConfirmSecureStorage(original *api.InitResponse, log *zap.Logger) error {
	fmt.Println("🔒 Please re-enter 3 unseal keys and the root token to confirm you've saved them.")

	rekeys, err := crypto.PromptSecrets("Unseal Key", 3, log)
	if err != nil {
		return err
	}
	reroot, err := crypto.PromptSecrets("Root Token", 1, log)
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

	log.Info("✅ Reconfirmation of unseal material passed")
	return nil
}

// ConfirmIrreversibleDeletion gets final consent before wiping unseal material.
func ConfirmIrreversibleDeletion(log *zap.Logger) error {
	fmt.Println("⚠️ Confirm irreversible deletion of unseal materials. This action is final.")
	fmt.Print("Type 'yes' to proceed: ")

	reader := bufio.NewReader(os.Stdin)
	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(strings.ToLower(resp))
	if resp != "yes" {
		return fmt.Errorf("user aborted deletion confirmation")
	}
	log.Info("🧹 User confirmed deletion of in-memory secrets")
	return nil
}

// SetVaultToken configures the Vault client to use a provided token.
func SetVaultToken(client *api.Client, token string) {
	client.SetToken(token)
}

// WaitForAgentToken polls for a token to appear at a given path, with a timeout.
func WaitForAgentToken(path string, log *zap.Logger) (string, error) {
	log.Info("⏳ Waiting for Vault agent token", zap.String("path", path))

	const maxWait = 30 * time.Second
	const interval = 500 * time.Millisecond
	start := time.Now()

	for time.Since(start) < maxWait {
		content, err := os.ReadFile(path)
		if err == nil && len(content) > 0 {
			token := strings.TrimSpace(string(content))
			log.Info("✅ Agent token found", zap.String("token_path", path))
			return token, nil
		}
		time.Sleep(interval)
	}
	return "", fmt.Errorf("agent token not found after %s", maxWait)
}
