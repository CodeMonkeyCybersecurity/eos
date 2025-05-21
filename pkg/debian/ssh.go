// pkg/system/ssh.go

package debian

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// GenerateFIPSKey creates a 4096-bit RSA key without passphrase
func GenerateFIPSKey(path string) error {
	cmd := exec.Command("ssh-keygen", "-t", "rsa", "-b", "4096", "-f", path, "-N", "")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh-keygen failed: %w", err)
	}
	return nil
}

// CopyKeyToRemote installs the SSH public key on the remote server
func CopyKeyToRemote(pubKeyPath, target string) error {
	cmd := exec.Command("ssh-copy-id", "-i", pubKeyPath, target)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh-copy-id failed: %w", err)
	}
	return nil
}

// AppendToSSHConfig appends a Host entry to SSH config if it doesn't already exist
func AppendToSSHConfig(alias, host, user, identityFile, configPath string) error {
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("could not determine home directory: %w", err)
		}
		configPath = filepath.Join(home, ".ssh", "config")
	}

	entry := fmt.Sprintf(`
Host %s
    HostName %s
    User %s
    IdentityFile %s
`, alias, host, user, identityFile)

	// Ensure file exists
	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open SSH config: %w", err)
	}
	defer shared.SafeClose(f)

	// Skip if already configured
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read SSH config: %w", err)
	}
	if strings.Contains(string(data), "Host "+alias) {
		return nil
	}

	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("failed to write SSH config: %w", err)
	}
	return nil
}

// CreateSSHKeys creates a 4096-bit SSH key pair for a given Linux user
func CreateSSHKeys(username string) error {
	home := "/home/" + username
	sshDir := filepath.Join(home, ".ssh")

	zap.L().Info("Creating SSH key for user", zap.String("username", username))

	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("mkdir failed: %w", err)
	}
	if err := execute.RunSimple("chown", "-R", username+":"+username, sshDir); err != nil {
		return fmt.Errorf("chown ssh dir failed: %w", err)
	}

	keyPath := filepath.Join(sshDir, "id_rsa")
	if err := execute.RunSimple("ssh-keygen", "-t", "rsa", "-b", "4096", "-N", "", "-f", keyPath); err != nil {
		return fmt.Errorf("ssh-keygen failed: %w", err)
	}
	if err := execute.RunSimple("chmod", "600", keyPath); err != nil {
		return fmt.Errorf("chmod private key failed: %w", err)
	}
	if err := execute.RunSimple("chown", username+":"+username, keyPath, keyPath+".pub"); err != nil {
		return fmt.Errorf("chown key files failed: %w", err)
	}

	return nil
}
