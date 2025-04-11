// pkg/crypto/certs.go

package crypto

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// EnsureCertificates checks if certificate files exist for the given domain,
// and if not, calls an external command (like certbot) to obtain them.
// It now accepts appName, baseDomain, and email as parameters.

func EnsureCertificates(appName, baseDomain, email string) error {
	certDir := "certs"
	// Construct the fully qualified domain name.
	fqdn := fmt.Sprintf("%s.%s", appName, baseDomain)
	privKey := filepath.Join(certDir, fmt.Sprintf("%s.privkey.pem", fqdn))
	fullChain := filepath.Join(certDir, fmt.Sprintf("%s.fullchain.pem", fqdn))

	// Check if the private key exists.
	if _, err := os.Stat(privKey); os.IsNotExist(err) {
		// Execute certbot to obtain a certificate.
		cmd := exec.Command("sudo", "certbot", "certonly", "--standalone",
			"--preferred-challenges", "http", "-d", fqdn, "-m", email,
			"--agree-tos", "--non-interactive")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to generate certificate: %w\nOutput: %s", err, output)
		}
		// In production, you would move or copy the generated certificates to certDir.
	} else if _, err := os.Stat(fullChain); os.IsNotExist(err) {
		// If the private key exists but the fullchain is missing, return an error.
		return fmt.Errorf("fullchain certificate missing for domain %s", fqdn)
	}

	// If both files exist, no action is needed.
	return nil
}
