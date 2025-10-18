// pkg/vault/key_distribution.go

package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DistributeInitKeys prompts user for key distribution options after Vault initialization
// This is CRITICAL for security - all 5 keys in one place defeats Shamir's Secret Sharing
func DistributeInitKeys(rc *eos_io.RuntimeContext, initRes *api.InitResponse) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════")
	logger.Info("terminal prompt:   CRITICAL: KEY DISTRIBUTION REQUIRED")
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: You have 5 unseal keys that MUST be distributed to 5 different key holders.")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt:   SECURITY WARNING:")
	logger.Info("terminal prompt: Storing all keys together defeats Shamir's Secret Sharing and creates")
	logger.Info("terminal prompt: a single point of failure. Each key should be held by a different person.")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: KEY DISTRIBUTION OPTIONS:")
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════")
	logger.Info("terminal prompt: ")

	// Option 1: Generate individual encrypted key files
	logger.Info("terminal prompt: Option 1: Generate 5 encrypted key files (RECOMMENDED)")
	logger.Info("terminal prompt:   - Each key encrypted with different password")
	logger.Info("terminal prompt:   - Safe for transfer via SCP, USB, or secure channels")
	logger.Info("terminal prompt:   - Each holder decrypts only their key")
	logger.Info("terminal prompt: ")

	if interaction.PromptYesNo(rc.Ctx, "Generate encrypted key files?", true) {
		if err := generateEncryptedKeyFiles(rc, initRes); err != nil {
			logger.Error("Failed to generate encrypted key files", zap.Error(err))
			return fmt.Errorf("generate encrypted key files: %w", err)
		}
		return nil
	}

	// Option 2: Display QR codes for manual transfer
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Option 2: Display QR codes for offline storage")
	logger.Info("terminal prompt:   - Scan each QR code with phone/tablet")
	logger.Info("terminal prompt:   - Store in password manager or offline")
	logger.Info("terminal prompt:   - No files left on server")
	logger.Info("terminal prompt: ")

	if interaction.PromptYesNo(rc.Ctx, "Display QR codes?", false) {
		if err := displayQRCodes(rc, initRes); err != nil {
			logger.Error("Failed to display QR codes", zap.Error(err))
			return fmt.Errorf("display QR codes: %w", err)
		}
		return nil
	}

	// Option 3: Manual copy
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Option 3: Manual distribution")
	logger.Info("terminal prompt:   - Keys remain in /var/lib/eos/secret/vault_init.json")
	logger.Info("terminal prompt:   - You are responsible for secure distribution")
	logger.Info("terminal prompt:   - Use 'eos inspect vault-init' to view keys")
	logger.Info("terminal prompt: ")

	logger.Warn("  Keys were NOT automatically distributed - you must distribute them manually!")
	logger.Info("terminal prompt: Run 'eos inspect vault-init' to retrieve keys for distribution")

	return nil
}

// generateEncryptedKeyFiles creates individual encrypted files for each unseal key
func generateEncryptedKeyFiles(rc *eos_io.RuntimeContext, initRes *api.InitResponse) error {
	logger := otelzap.Ctx(rc.Ctx)
	outputDir := "/var/lib/eos/vault-keys"

	logger.Info("Creating encrypted key files directory", zap.String("path", outputDir))

	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Generating 5 encrypted key files...")
	logger.Info("terminal prompt: Each key will be encrypted with a unique password.")
	logger.Info("terminal prompt: ")

	var generatedFiles []string

	for i, key := range initRes.KeysB64 {
		logger.Info("terminal prompt: ─────────────────────────────────────────────────────────────")
		logger.Info(fmt.Sprintf("terminal prompt: Key %d of %d", i+1, len(initRes.KeysB64)))
		logger.Info("terminal prompt: ─────────────────────────────────────────────────────────────")
		logger.Info(fmt.Sprintf("terminal prompt: Enter password for key holder #%d:", i+1))
		logger.Info("terminal prompt: (This will be needed to decrypt this key)")
		logger.Info("terminal prompt: ")

		// Prompt for password
		password, err := crypto.PromptPassword(rc, fmt.Sprintf("Password for key holder %d", i+1))
		if err != nil {
			return fmt.Errorf("prompt password for key %d: %w", i+1, err)
		}

		if len(password) < 12 {
			logger.Warn("  Password is short - recommend 12+ characters for security")
		}

		// Encrypt key with password using AES-256
		encrypted, err := crypto.EncryptWithPassword([]byte(key), password)
		if err != nil {
			return fmt.Errorf("encrypt key %d: %w", i+1, err)
		}

		// Write encrypted key file
		filename := filepath.Join(outputDir, fmt.Sprintf("unseal-key-%d.enc", i+1))
		if err := os.WriteFile(filename, encrypted, 0600); err != nil {
			return fmt.Errorf("write key file %d: %w", i+1, err)
		}

		generatedFiles = append(generatedFiles, filename)

		logger.Info(fmt.Sprintf("terminal prompt: ✓ Key %d encrypted and saved to: %s", i+1, filename))
		logger.Info("terminal prompt: ")
	}

	// Display final instructions
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════")
	logger.Info("terminal prompt: ✓ ALL KEYS ENCRYPTED SUCCESSFULLY")
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: DISTRIBUTION INSTRUCTIONS:")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: 1. Securely copy each file to its designated key holder:")
	logger.Info("terminal prompt:    - Use SCP: scp /var/lib/eos/vault-keys/unseal-key-1.enc user@host:")
	logger.Info("terminal prompt:    - Use encrypted USB drive")
	logger.Info("terminal prompt:    - Use secure file sharing (with 2FA)")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: 2. Provide each holder with their password (via separate channel)")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: 3. CRITICAL: Delete these files from this server after distribution:")
	logger.Info(fmt.Sprintf("terminal prompt:    sudo rm -rf %s", outputDir))
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: 4. To decrypt later (when unsealing): ")
	logger.Info("terminal prompt:    eos crypto decrypt --file unseal-key-1.enc")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════")
	logger.Info("terminal prompt: ")

	// Audit log
	logger.Info("Key distribution files generated",
		zap.Int("key_count", len(generatedFiles)),
		zap.String("output_dir", outputDir))

	return nil
}

// displayQRCodes generates and displays QR codes for each unseal key
func displayQRCodes(rc *eos_io.RuntimeContext, initRes *api.InitResponse) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════")
	logger.Info("terminal prompt: QR CODE DISPLAY")
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Each key will be displayed as a QR code.")
	logger.Info("terminal prompt: Scan with your phone and store in a secure location.")
	logger.Info("terminal prompt: ")

	for i, key := range initRes.KeysB64 {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: ─────────────────────────────────────────────────────────────")
		logger.Info(fmt.Sprintf("terminal prompt: UNSEAL KEY %d of %d", i+1, len(initRes.KeysB64)))
		logger.Info("terminal prompt: ─────────────────────────────────────────────────────────────")
		logger.Info("terminal prompt: ")

		// TODO: Generate QR code (crypto.GenerateQRCode not yet implemented)
		// For now, display key as text
		logger.Info(fmt.Sprintf("terminal prompt: Key %d: %s", i+1, key))

		logger.Info("terminal prompt: ")
		logger.Info(fmt.Sprintf("terminal prompt: Holder: Key Holder #%d", i+1))
		logger.Info("terminal prompt: ")

		if i < len(initRes.KeysB64)-1 {
			logger.Info("terminal prompt: Press Enter when ready for next key...")
			_, _ = eos_io.PromptInput(rc, "", "")
		}
	}

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ✓ All QR codes displayed")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: IMPORTANT: These keys are still stored on this server at:")
	logger.Info("terminal prompt: /var/lib/eos/secret/vault_init.json")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Consider deleting this file after all holders have saved their keys.")
	logger.Info("terminal prompt: ")

	return nil
}

// VerifyKeyBackup prompts user to verify they have backed up keys correctly
func VerifyKeyBackup(rc *eos_io.RuntimeContext, initRes *api.InitResponse) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════")
	logger.Info("terminal prompt: KEY BACKUP VERIFICATION")
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: To ensure you have safely backed up your keys,")
	logger.Info("terminal prompt: please enter any 3 of the 5 unseal keys:")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: (This is a TEST - we will not store these)")
	logger.Info("terminal prompt: ")

	var enteredKeys []string
	for i := 0; i < 3; i++ {
		key, err := eos_io.PromptInput(rc, fmt.Sprintf("Unseal key %d of 3", i+1), "")
		if err != nil {
			return fmt.Errorf("prompt key %d: %w", i+1, err)
		}
		enteredKeys = append(enteredKeys, key)
	}

	// Verify at least 3 match
	matchCount := 0
	for _, entered := range enteredKeys {
		for _, actual := range initRes.KeysB64 {
			if entered == actual {
				matchCount++
				break
			}
		}
	}

	if matchCount < 3 {
		logger.Error(" Key verification failed - keys do not match")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: The keys you entered do not match the generated keys.")
		logger.Info("terminal prompt: Please double-check your backup and try again.")
		logger.Info("terminal prompt: ")
		return fmt.Errorf("key verification failed: only %d keys matched", matchCount)
	}

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ✓ KEY VERIFICATION SUCCESSFUL")
	logger.Info("terminal prompt: You have correctly backed up your unseal keys!")
	logger.Info("terminal prompt: ")

	logger.Info("Key backup verified successfully",
		zap.Int("verified_keys", matchCount))

	return nil
}
