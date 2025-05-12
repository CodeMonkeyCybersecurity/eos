package create

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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
	CreateCmd.AddCommand(sshKeyCmd) // Fixed: Use the top-level cobra command
	sshKeyCmd.Flags().StringVar(&nameOverride, "name", "", "Optional basename for SSH key")
	sshKeyCmd.Flags().BoolVar(&printPrivate, "print-private", false, "Print private key to stdout")
	sshKeyCmd.Flags().BoolVar(&diskFallback, "disk-fallback", false, "Write to /home/eos/.ssh if Vault unavailable")
}

var sshKeyCmd = &cobra.Command{
	Use:   "ssh-key",
	Short: "Create and store an SSH key securely",
	RunE: func(cmd *cobra.Command, args []string) error {
		keyDir := "/home/eos/.ssh" // Or replace with shared.EosUserHome() if available
		baseName := nameOverride

		if baseName != "" && !isSafeName(baseName) {
			return fmt.Errorf("invalid --name: only alphanumeric, dashes, and underscores allowed")
		}

		client, err := vault.Auth()
		useVault := (err == nil)

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
			return fmt.Errorf("generate key: %w", err)
		}

		pubSSH, err := ssh.NewPublicKey(pub)
		if err != nil {
			return fmt.Errorf("encode public key: %w", err)
		}

		pubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubSSH)))
		privPEM := encodePrivateKeyPEM(priv)

		secretPath := fmt.Sprintf("pandora/%s", baseName)
		secret := map[string]string{
			"ssh-public":  pubStr,
			"ssh-private": string(privPEM),
		}

		if useVault {
			if err := vault.Write(client, secretPath, secret); err == nil {
				zap.L().Info("🔑 SSH key written to Vault", zap.String("path", "secret/"+secretPath))
				zap.L().Info("📎 Public key", zap.String("pubkey", pubStr))
				if printPrivate {
					fmt.Print(string(privPEM))
				}
				return nil
			}
			zap.L().Warn("⚠️ Vault write failed", zap.Error(err))
		}

		if !diskFallback {
			return errors.New("vault unavailable and --disk-fallback not set")
		}

		pubPath := filepath.Join(keyDir, fmt.Sprintf("id_ed25519-%s.pub", baseName))
		privPath := filepath.Join(keyDir, fmt.Sprintf("id_ed25519-%s", baseName))
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			return fmt.Errorf("create key dir: %w", err)
		}
		if err := os.WriteFile(pubPath, []byte(pubStr), 0644); err != nil {
			return fmt.Errorf("write pub: %w", err)
		}
		if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
			return fmt.Errorf("write priv: %w", err)
		}
		zap.L().Info("🔐 SSH key written to disk fallback", zap.String("path", privPath))
		zap.L().Info("📎 Public key", zap.String("pubkey", pubStr))
		if printPrivate {
			fmt.Print(string(privPEM))
		}
		return nil
	},
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isSafeName(name string) bool {
	ok, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, name)
	return ok
}
