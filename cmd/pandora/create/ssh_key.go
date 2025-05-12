package create

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

var (
	nameOverride string
	printPrivate bool
	diskFallback bool
)

func init() {
	CreateCmd.AddCommand(SshKeyCmd)
	SshKeyCmd.Flags().StringVar(&nameOverride, "name", "", "Optional basename for SSH key")
	SshKeyCmd.Flags().BoolVar(&printPrivate, "print-private", false, "Print private key to stdout")
	SshKeyCmd.Flags().BoolVar(&diskFallback, "disk-fallback", false, "Write to /home/eos/.ssh if Vault unavailable")
}

var SshKeyCmd = &cobra.Command{
	Use:   "ssh-key",
	Short: "Create and store an SSH key securely",
	RunE: eoscli.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		keyDir := "/home/eos/.ssh" // TODO: shared.EosUserHome()
		vaultPath := "pandora"

		// Determine base name for key
		name := nameOverride
		if name != "" && !isSafeName(name) {
			zap.L().Warn("Invalid --name provided", zap.String("name", name))
			return fmt.Errorf("invalid --name: only alphanumeric, dashes, and underscores allowed")
		}

		client, err := vault.Auth()
		useVault := err == nil

		// If name is not provided, or path exists, find next available name
		if useVault {
			checkFn := func(path string) (bool, error) {
				return vault.CheckVaultPathExists(client, path)
			}

			if name == "" {
				name, err = vault.FindNextAvailableVaultPath(vaultPath, checkFn)
				if err != nil {
					zap.L().Error("Could not find available Vault path", zap.Error(err))
					return fmt.Errorf("could not find available Vault path: %w", err)
				}
			} else {
				fullVaultPath := fmt.Sprintf("%s/%s", vaultPath, name)
				exists, err := checkFn(fullVaultPath)
				if err != nil {
					zap.L().Error("Vault path check failed", zap.String("path", fullVaultPath), zap.Error(err))
					return fmt.Errorf("vault path check failed: %w", err)
				}
				if exists {
					zap.L().Warn("Vault path already exists", zap.String("path", fullVaultPath))
					return fmt.Errorf("vault path already exists")
				}
			}
		}

		// Generate key
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("keygen failed: %w", err)
		}

		pubSSH, err := ssh.NewPublicKey(pub)
		if err != nil {
			return fmt.Errorf("encode public key failed: %w", err)
		}
		pubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubSSH)))
		privPEM := encodePrivateKeyPEM(priv)
		fingerprint := fingerprintSHA256(pubSSH)

		fullVaultPath := fmt.Sprintf("%s/%s", vaultPath, name)

		// Vault Write
		if useVault {
			if err := vault.WriteSSHKey(client, fullVaultPath, pubStr, string(privPEM), fingerprint); err == nil {
				zap.L().Info("🔐 SSH key written to Vault",
					zap.String("path", fullVaultPath),
					zap.String("fingerprint", fingerprint),
				)
				return nil
			} else {
				zap.L().Warn("Vault write failed, falling back to disk",
					zap.String("path", fullVaultPath),
					zap.Error(err),
				)
			}

			if !diskFallback {
				zap.L().Error("Vault write failed and disk fallback is disabled")
				return fmt.Errorf("vault write failed and disk fallback is disabled")
			}
		}

		// Disk fallback
		pubPath := filepath.Join(keyDir, fmt.Sprintf("id_ed25519-%s.pub", name))
		privPath := filepath.Join(keyDir, fmt.Sprintf("id_ed25519-%s", name))

		if err := os.MkdirAll(keyDir, 0700); err != nil {
			zap.L().Error("Failed to create .ssh directory", zap.String("dir", keyDir), zap.Error(err))
			return fmt.Errorf("mkdir failed: %w", err)
		}
		if err := os.WriteFile(pubPath, []byte(pubStr), 0644); err != nil {
			zap.L().Error("Failed to write public key", zap.String("path", pubPath), zap.Error(err))
			return fmt.Errorf("write public key failed: %w", err)
		}
		if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
			zap.L().Error("Failed to write private key", zap.String("path", privPath), zap.Error(err))
			return fmt.Errorf("write private key failed: %w", err)
		}

		zap.L().Info("🔐 SSH key written to disk",
			zap.String("private_key_path", privPath),
			zap.String("public_key_path", pubPath),
		)
		return nil
	}),
}

func encodePrivateKeyPEM(key ed25519.PrivateKey) []byte {
	block := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: key.Seed(), // optional: switch to ssh.MarshalED25519PrivateKey
	}
	var buf bytes.Buffer
	_ = pem.Encode(&buf, block)
	return buf.Bytes()
}

func fingerprintSHA256(pub ssh.PublicKey) string {
	hash := sha256.Sum256(pub.Marshal())
	return fmt.Sprintf("SHA256:%s", base64.StdEncoding.EncodeToString(hash[:]))
}

func isSafeName(name string) bool {
	ok, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, name)
	return ok
}
