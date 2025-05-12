package create

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
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
		logger := zap.L()
		keyDir := "/home/eos/.ssh" // TODO: Replace with shared.EosUserHome() if standardized
		baseName := nameOverride

		if baseName != "" && !isSafeName(baseName) {
			logger.Error("Invalid --name: only alphanumeric, dashes, and underscores allowed", zap.String("name", baseName))
			return errors.New("invalid --name")
		}

		client, err := vault.Auth()
		useVault := (err == nil)
		if !useVault {
			logger.Warn("Vault unavailable", zap.Error(err))
		}

		if baseName == "" {
			for i := 1; ; i++ {
				test := fmt.Sprintf("ssh-key-%03d", i)
				diskPath := filepath.Join(keyDir, fmt.Sprintf("id_ed25519-%03d", i))
				if !fileExists(diskPath) {
					baseName = test
					break
				}
			}
		}

		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			logger.Error("Failed to generate SSH key", zap.Error(err))
			return err
		}

		pubSSH, err := ssh.NewPublicKey(pub)
		if err != nil {
			logger.Error("Failed to encode public key", zap.Error(err))
			return err
		}

		pubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubSSH)))
		privPEM := encodePrivateKeyPEM(priv)

		// 🎯 NEW: Compute fingerprint
		fp := fingerprintSHA256(pubSSH)

		vaultPath := "pandora"
		name := baseName
		fullVaultPath := fmt.Sprintf("%s/%s", vaultPath, name)

		secret := map[string]string{
			"ssh-public":  pubStr,
			"ssh-private": string(privPEM),
			"fingerprint": fp, // 🎯 store fingerprint in Vault too
		}

		if useVault {
			if err := vault.Write(client, fullVaultPath, secret); err == nil {
				logger.Info("🔑 SSH key written to Vault",
					zap.String("vaultPath", fullVaultPath),
					zap.String("name", name),
				)
				logger.Info("📎 Public key", zap.String("pubkey", pubStr))
				logger.Info("🔍 Fingerprint (SHA256)", zap.String("fingerprint", fp))
				if printPrivate {
					logger.Info("📜 Private key", zap.String("private", string(privPEM)))
				}
				return nil
			}
			logger.Warn("⚠️ Vault write failed", zap.Error(err))
		}

		if !diskFallback {
			logger.Error("Vault write failed and --disk-fallback not set")
			return errors.New("vault write failed and no fallback permitted")
		}

		pubPath := filepath.Join(keyDir, fmt.Sprintf("id_ed25519-%s.pub", baseName))
		privPath := filepath.Join(keyDir, fmt.Sprintf("id_ed25519-%s", baseName))

		if err := os.MkdirAll(keyDir, 0700); err != nil {
			logger.Error("Failed to create key directory", zap.String("path", keyDir), zap.Error(err))
			return err
		}
		if err := os.WriteFile(pubPath, []byte(pubStr), 0644); err != nil {
			logger.Error("Failed to write public key", zap.String("path", pubPath), zap.Error(err))
			return err
		}
		if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
			logger.Error("Failed to write private key", zap.String("path", privPath), zap.Error(err))
			return err
		}

		logger.Info("🔐 SSH key written to disk fallback", zap.String("path", privPath))
		logger.Info("📎 Public key", zap.String("pubkey", pubStr))
		logger.Info("🔍 Fingerprint (SHA256)", zap.String("fingerprint", fp))
		if printPrivate {
			logger.Info("📜 Private key", zap.String("private", string(privPEM)))
		}
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isSafeName(name string) bool {
	ok, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, name)
	return ok
}
