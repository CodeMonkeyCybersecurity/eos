// pkg/vault/export.go

package vault

import (
	"fmt"
	"os/exec"

	"go.uber.org/zap"
)

// ExportTLSCert copies the Vault TLS certificate to a remote machine using SCP.
func ExportTLSCert(remoteUser, remoteHost, remotePath string, log *zap.Logger) error {
	localPath := "/opt/vault/tls/tls.crt"
	dest := fmt.Sprintf("%s@%s:%s", remoteUser, remoteHost, remotePath)

	cmd := exec.Command("scp", localPath, dest)
	log.Info("📤 Exporting Vault TLS cert via SCP", zap.String("source", localPath), zap.String("destination", dest))

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("❌ SCP command failed", zap.Error(err), zap.ByteString("output", output))
		return fmt.Errorf("scp failed: %w", err)
	}

	log.Info("✅ TLS cert exported successfully", zap.ByteString("output", output))
	return nil
}

var (
	User    string
	Host    string
	Path    string
	TlsCert bool
)
