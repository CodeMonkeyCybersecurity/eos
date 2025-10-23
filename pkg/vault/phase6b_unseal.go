// pkg/vault/phase6b_unseal.go

package vault

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// createUnauthenticatedVaultClient creates a Vault client without authentication
// Used to check Vault status (init/seal) before authentication is available
func createUnauthenticatedVaultClient(rc *eos_io.RuntimeContext) (*api.Client, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug(" Creating unauthenticated Vault client for status checks")

	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://shared.GetInternalHostname:8200"
		logger.Debug(" VAULT_ADDR not set, using default",
			zap.String("default_addr", vaultAddr))
	} else {
		logger.Debug(" Using VAULT_ADDR from environment",
			zap.String("vault_addr", vaultAddr))
	}

	config := api.DefaultConfig()
	config.Address = vaultAddr
	logger.Debug(" Vault client config created",
		zap.String("address", config.Address))

	// Handle self-signed certificates (common for new Vault installations)
	skipVerify := os.Getenv("VAULT_SKIP_VERIFY")
	if skipVerify == "1" {
		logger.Debug(" VAULT_SKIP_VERIFY enabled - configuring TLS to skip verification",
			zap.String("reason", "self-signed certificates during initial setup"))
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 - intentional for self-signed certs
		}
		config.HttpClient.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
		logger.Debug(" TLS skip verification configured successfully")
	} else {
		logger.Debug(" VAULT_SKIP_VERIFY not set - using standard TLS verification",
			zap.String("skip_verify_value", skipVerify))
	}

	client, err := api.NewClient(config)
	if err != nil {
		logger.Error(" Failed to create unauthenticated Vault client",
			zap.Error(err),
			zap.String("vault_addr", vaultAddr),
			zap.String("skip_verify", skipVerify))
		return nil, fmt.Errorf("create vault API client: %w", err)
	}

	logger.Info(" Unauthenticated Vault client created successfully",
		zap.String("vault_addr", config.Address),
		zap.Bool("skip_verify", skipVerify == "1"))
	return client, nil
}

func UnsealVault(rc *eos_io.RuntimeContext) (*api.Client, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Entering UnsealVault")

	// CRITICAL P0: Check init status BEFORE attempting authentication
	// Unauthenticated client is sufficient to check Vault status
	logger.Debug(" Step 1: Creating unauthenticated client to check Vault init status")
	unauthClient, err := createUnauthenticatedVaultClient(rc)
	if err != nil {
		logger.Error(" Failed to create unauthenticated Vault client",
			zap.Error(err),
			zap.String("remediation", "Check VAULT_ADDR environment variable and network connectivity"))
		return nil, fmt.Errorf("create unauthenticated vault client: %w", err)
	}
	logger.Debug(" Unauthenticated client created, proceeding to check init status")

	logger.Debug(" Step 2: Checking Vault initialization status")
	initStatus, err := unauthClient.Sys().InitStatus()
	if err != nil {
		logger.Error(" Failed to check Vault init status",
			zap.Error(err),
			zap.String("vault_addr", unauthClient.Address()),
			zap.String("remediation", "Ensure Vault service is running: systemctl status vault"))
		return nil, fmt.Errorf("check init status: %w", err)
	}
	logger.Info(" Vault init status retrieved successfully",
		zap.Bool("initialized", initStatus),
		zap.String("vault_addr", unauthClient.Address()))

	if initStatus {
		logger.Info(" Vault is already initialized - entering re-run/recovery path")

		// CRITICAL P0: During initial setup, Vault Agent/AppRole don't exist yet
		// Use root token from vault_init.json instead of trying fancy auth methods
		logger.Info(" Step 3: Loading root token from vault_init.json",
			zap.String("reason", "Vault Agent/AppRole not configured yet during initial setup"),
			zap.String("path", shared.VaultInitPath))
		initRes, err := LoadOrPromptInitResult(rc)
		if err != nil {
			logger.Error(" Failed to load Vault init credentials",
				zap.Error(err),
				zap.String("expected_path", shared.VaultInitPath),
				zap.String("remediation", "Ensure vault_init.json exists or re-enter credentials when prompted"))
			return nil, fmt.Errorf("load vault init credentials: %w", err)
		}
		logger.Debug(" Init credentials loaded successfully",
			zap.Int("unseal_keys_count", len(initRes.KeysB64)),
			zap.Bool("has_root_token", initRes.RootToken != ""))

		// Set root token on unauthenticated client
		logger.Debug(" Step 4: Setting root token on client for authenticated operations")
		unauthClient.SetToken(initRes.RootToken)
		logger.Info(" Root token applied to Vault client")

		// Verify token works
		logger.Debug(" Step 5: Verifying root token is valid and has correct permissions")
		if !VerifyToken(rc, unauthClient, initRes.RootToken) {
			logger.Error(" Root token verification failed",
				zap.String("remediation", "Token may be expired or invalid. Check vault_init.json integrity"))
			return nil, fmt.Errorf("root token verification failed")
		}
		logger.Info(" Root token verified successfully - client is authenticated")

		client := unauthClient

		logger.Debug(" Step 6: Checking Vault seal status")
		sealStatus, err := client.Sys().SealStatus()
		if err != nil {
			logger.Error(" Failed to check Vault seal status",
				zap.Error(err),
				zap.String("vault_addr", client.Address()),
				zap.String("remediation", "Ensure Vault API is accessible"))
			return nil, fmt.Errorf("check seal status: %w", err)
		}
		logger.Info(" Vault seal status retrieved",
			zap.Bool("sealed", sealStatus.Sealed),
			zap.Int("seal_threshold", sealStatus.T),
			zap.Int("seal_shares", sealStatus.N))

		if sealStatus.Sealed {
			logger.Warn(" Vault is initialized but SEALED - unseal required",
				zap.Int("progress", sealStatus.Progress),
				zap.Int("threshold", sealStatus.T))

			logger.Info(" Step 7: Loading unseal keys from vault_init.json")
			initRes, loadErr := LoadOrPromptInitResult(rc)
			credentialsFromPrompt := false
			if loadErr != nil {
				logger.Warn(" Failed to load vault_init.json, falling back to interactive prompt",
					zap.Error(loadErr),
					zap.String("expected_path", shared.VaultInitPath))

				// PROMPT user as final fallback
				logger.Info(" Prompting user for unseal keys and root token interactively")
				keys, err := interaction.PromptSecrets(rc.Ctx, "Unseal Key", 3)
				if err != nil {
					logger.Error(" Failed to prompt for unseal keys", zap.Error(err))
					return nil, fmt.Errorf("prompt unseal keys failed: %w", err)
				}
				root, err := interaction.PromptSecrets(rc.Ctx, "Root Token", 1)
				if err != nil {
					logger.Error(" Failed to prompt for root token", zap.Error(err))
					return nil, fmt.Errorf("prompt root token failed: %w", err)
				}
				initRes = &api.InitResponse{
					KeysB64:   keys,
					RootToken: root[0],
				}
				credentialsFromPrompt = true
				logger.Info(" Interactive credentials received from user")
			}
			logger.Info(" Unseal credentials ready",
				zap.Int("keys_available", len(initRes.KeysB64)),
				zap.Bool("from_prompt", credentialsFromPrompt))

			logger.Info(" Step 8: Unsealing Vault with unseal keys")
			if err := Unseal(rc, client, initRes); err != nil {
				logger.Error(" Vault unseal operation failed",
					zap.Error(err),
					zap.String("remediation", "Verify unseal keys are correct"))
				return nil, fmt.Errorf("unseal vault: %w", err)
			}

			// POST-UNSEAL CHECK
			logger.Debug(" Verifying Vault unseal was successful")
			status, err := client.Sys().SealStatus()
			if err != nil {
				logger.Warn(" Failed to verify unseal status (non-fatal)", zap.Error(err))
			} else if status.Sealed {
				logger.Error(" Vault remains SEALED after unseal attempt",
					zap.Int("progress", status.Progress),
					zap.Int("threshold", status.T),
					zap.String("remediation", "Insufficient or incorrect unseal keys provided"))
				return nil, fmt.Errorf("vault remains sealed after unseal attempt")
			}
			logger.Info(" Vault unsealed successfully")

			// CRITICAL FIX P0: Save credentials if they were provided interactively
			// This prevents infinite prompt loops when vault_init.json is missing
			if credentialsFromPrompt {
				otelzap.Ctx(rc.Ctx).Info(" Saving credentials from interactive prompt to prevent future prompts")
				if err := SaveInitResult(rc, initRes); err != nil {
					otelzap.Ctx(rc.Ctx).Warn("Failed to save credentials (non-fatal)", zap.Error(err))
					otelzap.Ctx(rc.Ctx).Info("terminal prompt: You may be prompted for credentials again in future operations")
					otelzap.Ctx(rc.Ctx).Info("terminal prompt: To fix this, securely save your keys and token")
				} else {
					otelzap.Ctx(rc.Ctx).Info(" Credentials saved successfully", zap.String("path", shared.VaultInitPath))
					otelzap.Ctx(rc.Ctx).Info("terminal prompt: Vault credentials saved - future operations won't prompt")
				}
			}
		} else {
			logger.Info(" Vault is already unsealed - ready for operations")
		}

		logger.Info(" UnsealVault completed successfully (already-initialized path)",
			zap.Bool("was_sealed", sealStatus.Sealed))
		return client, nil
	}

	// Vault NOT initialized - fresh installation path
	logger.Info(" Vault is NOT initialized - entering fresh installation path")
	logger.Info(" Step 3: Initializing Vault for the first time",
		zap.String("shares", "5"),
		zap.String("threshold", "3"))

	// Use unauthenticated client for initialization (no auth needed for /sys/init)
	initRes, err := initVaultWithTimeout(rc, unauthClient)
	if err != nil {
		logger.Error(" Vault initialization failed",
			zap.Error(err),
			zap.String("vault_addr", unauthClient.Address()),
			zap.String("remediation", "Check Vault logs: journalctl -u vault -n 50"))
		return nil, err
	}
	logger.Info(" Vault initialized successfully",
		zap.Int("unseal_keys_generated", len(initRes.Keys)),
		zap.Int("base64_keys_generated", len(initRes.KeysB64)),
		zap.Bool("has_root_token", initRes.RootToken != ""))

	logger.Info(" Step 4: Handling initialization material (keys, token)")
	if err := handleInitMaterial(rc, initRes); err != nil {
		logger.Error(" Failed to handle initialization material",
			zap.Error(err),
			zap.String("remediation", "Initialization succeeded but credential handling failed"))
		return nil, err
	}
	logger.Info(" Initialization material handled successfully")

	// Set root token on unauthenticated client to make it authenticated
	logger.Debug(" Step 5: Setting root token on client for post-initialization operations")
	unauthClient.SetToken(initRes.RootToken)
	logger.Info(" Root token set on client - client is now authenticated")

	logger.Info(" Step 6: Finalizing Vault setup (unseal + persist credentials)")
	if err := finalizeVaultSetup(rc, unauthClient, initRes); err != nil {
		logger.Error(" Failed to finalize Vault setup",
			zap.Error(err),
			zap.String("remediation", "Vault is initialized but finalization failed"))
		return nil, err
	}
	logger.Info(" Vault setup finalized successfully")

	logger.Info(" UnsealVault completed successfully (fresh-initialization path)")
	return unauthClient, nil
}

func initVaultWithTimeout(rc *eos_io.RuntimeContext, client *api.Client) (*api.InitResponse, error) {
	otelzap.Ctx(rc.Ctx).Info(" Starting initVaultWithTimeout")

	initRes, err := client.Sys().InitWithContext(rc.Ctx, &api.InitRequest{SecretShares: 5, SecretThreshold: 3})
	if err == nil {
		otelzap.Ctx(rc.Ctx).Info(" Vault init successful")
		return initRes, nil
	}

	otelzap.Ctx(rc.Ctx).Warn("Vault init failed, evaluating error", zap.Error(err))

	if IsAlreadyInitialized(err) {
		otelzap.Ctx(rc.Ctx).Warn("Vault already initialized, loading init result")
		return LoadOrPromptInitResult(rc)
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return nil, fmt.Errorf("vault init timed out: %w", err)
	}
	if strings.Contains(err.Error(), "connection refused") {
		return nil, fmt.Errorf("vault connection refused: %w", err)
	}

	return nil, fmt.Errorf("vault init error: %w", err)
}

func handleInitMaterial(rc *eos_io.RuntimeContext, initRes *api.InitResponse) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Handling init material")

	if len(initRes.Keys) == 0 || initRes.RootToken == "" {
		return fmt.Errorf("invalid init result: missing keys or root token")
	}

	// STEP 1: Save credentials to file FIRST (backup/recovery)
	logger.Info(" Saving Vault initialization credentials securely")
	if err := SaveInitResult(rc, initRes); err != nil {
		return fmt.Errorf("failed to save init credentials: %w", err)
	}
	logger.Info(" Credentials saved to file", zap.String("path", shared.VaultInitPath))

	// STEP 2: Display prominent instructions and PAUSE for user to save externally
	printVaultInitializationInstructions()

	// STEP 3: Wait for user to confirm they've saved the credentials
	logger.Info("terminal prompt: Press ENTER after you have SAVED the credentials to your password manager...")
	fmt.Fprintf(os.Stderr, "Press ENTER to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

	// STEP 4: Verify they saved it by re-entering credentials
	if err := ConfirmUnsealMaterialSaved(rc, initRes); err != nil {
		return fmt.Errorf("credential confirmation failed: %w", err)
	}

	// STEP 5: Offer to delete local file (best practice for production)
	if shouldDeleteLocalCredentials(rc) {
		logger.Warn(" Deleting local credentials file - ensure you have saved them externally!")
		logger.Info("terminal prompt: Deleting local credential file for security")

		if err := os.Remove(shared.VaultInitPath); err != nil {
			logger.Warn("Failed to delete local credentials file", zap.Error(err))
			// Don't fail - this is optional cleanup
		} else {
			logger.Info(" Local credentials file deleted successfully")
			fmt.Fprintln(os.Stderr, "\n✓ Local credentials file deleted for security")
			fmt.Fprintln(os.Stderr, "  Credentials only exist in your password manager now.")
		}
	} else {
		logger.Info(" Keeping local credentials file")
		fmt.Fprintln(os.Stderr, "\nℹ Local credentials file kept at: "+shared.VaultInitPath)
		fmt.Fprintln(os.Stderr, "  Consider deleting this file after distributing keys to operators.")
	}

	return nil
}

// printVaultInitializationInstructions displays clear, prominent instructions
// for saving Vault initialization credentials (Tier 2 security best practice)
func printVaultInitializationInstructions() {
	fmt.Fprintln(os.Stderr, "\n"+strings.Repeat("=", 70))
	fmt.Fprintln(os.Stderr, "    VAULT INITIALIZED SUCCESSFULLY")
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 70))
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "CRITICAL: Your unseal keys and root token are ready.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "WITHOUT THESE CREDENTIALS YOU CANNOT RECOVER YOUR VAULT!")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 70))
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, " STEP 1: Open a SECOND terminal session and run:")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "    sudo cat /var/lib/eos/secret/vault_init.json")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "    OR")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "    sudo eos read vault-init")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, " STEP 2: Copy ALL credentials to your password manager:")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "    • All 5 unseal keys (you need 3 minimum to unseal)")
	fmt.Fprintln(os.Stderr, "    • Root token (provides admin access)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, " STEP 3: Verify you saved them correctly!")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "   Recommended password managers:")
	fmt.Fprintln(os.Stderr, "    • 1Password (use Secure Notes)")
	fmt.Fprintln(os.Stderr, "    • Bitwarden (use Secure Notes)")
	fmt.Fprintln(os.Stderr, "    • KeePassXC (use Notes field)")
	fmt.Fprintln(os.Stderr, "    • Encrypted file on separate device")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  PRODUCTION TIP:")
	fmt.Fprintln(os.Stderr, "   For high security, distribute different keys to different operators")
	fmt.Fprintln(os.Stderr, "   (Shamir's Secret Sharing - requires 3 of 5 keys to unseal)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 70))
	fmt.Fprintln(os.Stderr, "")
}

// shouldDeleteLocalCredentials asks user if they want to delete the local file
func shouldDeleteLocalCredentials(rc *eos_io.RuntimeContext) bool {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, strings.Repeat("-", 70))
	fmt.Fprintln(os.Stderr, "SECURITY RECOMMENDATION:")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "For production environments, you should DELETE the local credentials file")
	fmt.Fprintln(os.Stderr, "after you've saved them to your password manager.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "This prevents all keys from being stored in one location.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "For development/lab environments, keeping the file is fine for convenience.")
	fmt.Fprintln(os.Stderr, strings.Repeat("-", 70))
	fmt.Fprintln(os.Stderr, "")

	return interaction.PromptYesNo(
		rc.Ctx,
		"Delete local credentials file? (you MUST have saved them externally first)",
		false, // Default: no (safe default)
	)
}

func finalizeVaultSetup(rc *eos_io.RuntimeContext, client *api.Client, initRes *api.InitResponse) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Entering finalizeVaultSetup")
	logger.Debug(" Finalization steps: unseal → set token → store client → persist credentials")

	logger.Debug(" Step 1: Unsealing Vault with initialization keys")
	if err := Unseal(rc, client, initRes); err != nil {
		logger.Error(" Vault unseal failed during finalization",
			zap.Error(err),
			zap.String("remediation", "Check unseal keys are valid"))
		return fmt.Errorf("unseal during finalization: %w", err)
	}
	logger.Info(" Vault unsealed successfully")

	logger.Debug(" Step 2: Setting root token on client")
	client.SetToken(initRes.RootToken)
	logger.Info(" Root token set on Vault client")

	// CRITICAL P0: Store client in context BEFORE any operations
	// This prevents re-authentication attempts during subsequent operations
	logger.Debug(" Step 3: Storing authenticated client in RuntimeContext",
		zap.String("reason", "Prevents re-authentication attempts"))
	SetVaultClient(rc, client)
	logger.Info(" Vault client stored in context successfully")

	// NOTE: We do NOT write vault_init to Vault KV here because:
	// 1. KV secrets engine hasn't been enabled yet (that's Phase 9a)
	// 2. Credentials are already saved to disk in handleInitMaterial()
	// 3. Writing to KV before Phase 9a causes "404 no handler for route" error
	//
	// If needed in the future, vault_init can be uploaded to KV in Phase 9b
	// (after KV engine is enabled) using the disk-persisted copy.
	logger.Debug(" Step 4: Init credentials saved to disk",
		zap.String("path", "/var/lib/eos/secret/vault_init.json"),
		zap.String("note", "Will sync to Vault KV in Phase 9b after KV engine is enabled"))

	logger.Info(" finalizeVaultSetup completed successfully")
	return nil
}

func Unseal(rc *eos_io.RuntimeContext, client *api.Client, init *api.InitResponse) error {
	otelzap.Ctx(rc.Ctx).Info(" Submitting unseal keys to Vault")
	for i := 0; i < 3; i++ {
		otelzap.Ctx(rc.Ctx).Debug(" Submitting unseal key", zap.Int("index", i))
		resp, err := client.Sys().Unseal(init.KeysB64[i])
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error(" Unseal key submission failed", zap.Int("index", i), zap.Error(err))
			return fmt.Errorf("unseal key %d failed: %w", i+1, err)
		}
		otelzap.Ctx(rc.Ctx).Info(" Unseal key accepted", zap.Int("submitted", i+1), zap.Bool("sealed", resp.Sealed))
		if !resp.Sealed {
			otelzap.Ctx(rc.Ctx).Info(" Vault is unsealed")
			return nil
		}
	}
	return errors.New("vault remains sealed after 3 unseal keys")
}

func ConfirmUnsealMaterialSaved(rc *eos_io.RuntimeContext, init *api.InitResponse) error {
	logger := otelzap.Ctx(rc.Ctx)

	// P1 UX IMPROVEMENT: Allow 3 attempts instead of instant fail
	// This helps users who make typos, copy with quotes, or add extra whitespace
	const maxAttempts = 3

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			logger.Info("terminal prompt: ")
			logger.Info(fmt.Sprintf("terminal prompt: Attempt %d of %d - Please try again", attempt, maxAttempts))
		}

		logger.Info("terminal prompt: Re-enter 3 unseal keys + root token to confirm you've saved them.")
		logger.Info("terminal prompt: TIP: Copy the EXACT keys from vault_init.json")
		logger.Info("terminal prompt:      Remove any quotes, spaces, or newlines")
		logger.Info("terminal prompt:      Example: \"key123\" should be entered as: key123")

		keys, err := interaction.PromptSecrets(rc.Ctx, "Unseal Key", 3)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error(" Failed to prompt unseal keys", zap.Error(err))
			return err
		}

		root, err := interaction.PromptSecrets(rc.Ctx, "Root Token", 1)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error(" Failed to prompt root token", zap.Error(err))
			return err
		}

		// P1 UX IMPROVEMENT: Trim whitespace and quotes from user input
		// This prevents failures due to copy-paste artifacts
		for i := range keys {
			keys[i] = strings.TrimSpace(keys[i])  // Remove leading/trailing whitespace
			keys[i] = strings.Trim(keys[i], `"'`) // Remove quotes if present
		}
		rootTokenInput := strings.TrimSpace(root[0])
		rootTokenInput = strings.Trim(rootTokenInput, `"'`)

		// Verify root token
		if crypto.HashString(rootTokenInput) != crypto.HashString(init.RootToken) {
			if attempt < maxAttempts {
				logger.Warn(" Root token mismatch, please try again",
					zap.Int("attempt", attempt),
					zap.Int("remaining", maxAttempts-attempt))
				continue // Try again
			}
			otelzap.Ctx(rc.Ctx).Error(" Root token mismatch after maximum attempts",
				zap.Int("attempts", maxAttempts))
			return fmt.Errorf("root token mismatch after %d attempts", maxAttempts)
		}

		// Verify unseal keys
		match := 0
		for _, entered := range keys {
			// Check against both base64 keys (KeysB64) and hex keys (Keys)
			// Users might copy either format from the JSON file
			matched := false

			// Try base64 format first (most common)
			for _, known := range init.KeysB64 {
				if crypto.HashString(entered) == crypto.HashString(known) {
					match++
					matched = true
					break
				}
			}

			// If not matched in base64, try hex format
			if !matched && len(init.Keys) > 0 {
				for _, known := range init.Keys {
					if crypto.HashString(entered) == crypto.HashString(known) {
						match++
						break
					}
				}
			}
		}

		if match >= 3 {
			// Success!
			otelzap.Ctx(rc.Ctx).Info(" User confirmed unseal material backup")
			return nil
		}

		// Not enough matches
		if attempt < maxAttempts {
			logger.Warn(" Credential confirmation failed, please try again",
				zap.Int("matched", match),
				zap.Int("required", 3),
				zap.Int("attempt", attempt),
				zap.Int("remaining", maxAttempts-attempt))
			logger.Info("terminal prompt: ")
			logger.Info(fmt.Sprintf("terminal prompt: Only %d of 3 keys matched. Double-check your keys.", match))
		} else {
			logger.Error(" Credential confirmation failed after maximum attempts",
				zap.Int("attempts", maxAttempts),
				zap.Int("last_match", match))
			logger.Debug("Comparison details",
				zap.Int("entered_keys", len(keys)),
				zap.Int("available_base64_keys", len(init.KeysB64)),
				zap.Int("available_hex_keys", len(init.Keys)))
			return fmt.Errorf("credential confirmation failed after %d attempts (got %d matches on last attempt)", maxAttempts, match)
		}
	}

	// Should never reach here, but just in case
	return fmt.Errorf("unexpected error in credential confirmation")
}
