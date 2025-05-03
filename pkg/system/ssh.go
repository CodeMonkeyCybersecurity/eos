// pkg/system/ssh.go
package system

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// GenerateFIPSKey generates a FIPS-compliant RSA SSH key (2048 bits, no passphrase)
func GenerateFIPSKey(path string) error {
	cmd := exec.Command( "ssh-keygen", "-t", "rsa", "-b", "4096", "-f", path, "-N", "")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// CopyKeyToRemote runs ssh-copy-id to install the public key to a remote system
func CopyKeyToRemote(pubKeyPath, target string) error {
	cmd := exec.Command( "ssh-copy-id", "-i", pubKeyPath, target)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// AppendToSSHConfig appends an SSH Host block for the target host using the provided identity file
func AppendToSSHConfig(alias, host, user, identityFile, configPath string) error {
	entry := fmt.Sprintf(`
Host %s
    HostName %s
    User %s
    IdentityFile %s
`, alias, host, user, identityFile)

	// Create the config file if it doesn't exist
	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open SSH config: %w", err)
	}
	defer shared.SafeClose(f)

	// Only add entry if not already present
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read SSH config: %w", err)
	}
	if strings.Contains(string(data), "Host "+host) {
		return nil // already configured
	}

	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("failed to write to SSH config: %w", err)
	}

	return nil
}
