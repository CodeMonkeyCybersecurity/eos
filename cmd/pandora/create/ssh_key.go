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

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		keyDir := "/home/eos/.ssh" // TODO: shared.EosUserHome()
		// our KV-v2 mount + base directory
		const mount = "secret"
		const baseDir = "pandora"
		const leafBase = "ssh-key"

		// vaultPath (directory) is fixed:
		vaultDir := baseDir
		// Determine base name for key
		name := nameOverride
		if name != "" && !isSafeName(name) {
			otelzap.Ctx(rc.Ctx).Warn("Invalid --name provided", zap.String("name", name))
			return fmt.Errorf("invalid --name: only alphanumeric, dashes, and underscores allowed")
		}

		// Authenticate to Vault
		client, err := vault.Authn(rc)
		// declare a local flag
		useVault := (err == nil)
		if !useVault {
			otelzap.Ctx(rc.Ctx).Warn("Vault unavailable — will fallback to disk", zap.Error(err))
		}

		// if Vault is up, pick the first free suffix
		if useVault {
			// find the first free leaf under "eos/pandora"
			leaf, err := vault.FindNextAvailableKVv2Path(rc, client, mount, baseDir, leafBase)
			if err != nil {
				otelzap.Ctx(rc.Ctx).Error("no available Vault path", zap.Error(err))
				return err
			}
			// leaf == "eos/pandora/ssh-key" or ".../ssh-key-001"
			// extract just the final segment
			name = filepath.Base(leaf)
		}

		chosen := fmt.Sprintf("%s/%s", vaultDir, name)
		otelzap.Ctx(rc.Ctx).Info(" Chosen Vault path for new SSH key", zap.String("path", chosen))

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

		fullVaultPath := fmt.Sprintf("%s/%s", vaultDir, name)

		// Vault Write
		if useVault {
			// Extract a real context.Context from your RuntimeContext:
			if err := vault.WriteSSHKey(
				rc,
				client,
				mount, // must supply the KV-v2 mount
				fullVaultPath,
				pubStr,
				string(privPEM),
				fingerprint,
			); err == nil {
				otelzap.Ctx(rc.Ctx).Info(" SSH key written to Vault",
					zap.String("path", fullVaultPath),
					zap.String("fingerprint", fingerprint),
				)
				return nil
			} else {
				otelzap.Ctx(rc.Ctx).Warn("Vault write failed, falling back to disk",
					zap.String("path", fullVaultPath),
					zap.Error(err),
				)
			}

			if !diskFallback {
				otelzap.Ctx(rc.Ctx).Error("Vault write failed and disk fallback is disabled")
				return fmt.Errorf("vault write failed and disk fallback is disabled")
			}
		}

		// Disk fallback
		pubPath := filepath.Join(keyDir, fmt.Sprintf("id_ed25519-%s.pub", name))
		privPath := filepath.Join(keyDir, fmt.Sprintf("id_ed25519-%s", name))

		if err := os.MkdirAll(keyDir, 0700); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to create .ssh directory", zap.String("dir", keyDir), zap.Error(err))
			return fmt.Errorf("mkdir failed: %w", err)
		}
		if err := os.WriteFile(pubPath, []byte(pubStr), 0644); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to write public key", zap.String("path", pubPath), zap.Error(err))
			return fmt.Errorf("write public key failed: %w", err)
		}
		if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to write private key", zap.String("path", privPath), zap.Error(err))
			return fmt.Errorf("write private key failed: %w", err)
		}

		otelzap.Ctx(rc.Ctx).Info(" SSH key written to disk",
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
