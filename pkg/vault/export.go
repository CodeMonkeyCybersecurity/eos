// pkg/vault/export.go

package vault

import (
	"fmt"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TLSExportInput represents the input required to export a TLS cert.
type TLSExportInput struct {
	User string `validate:"required"`
	Host string `validate:"required"`
	Path string `validate:"required"`
}

var (
	User string
	Host string
	Path string
)

// ExportTLSCert copies the Vault TLS certificate to a remote machine using SCP.
func ExportTLSCert(rc *eos_io.RuntimeContext, input TLSExportInput) error {
	log := otelzap.Ctx(rc.Ctx)

	// Validate input using go-playground/validator
	if err := verify.Struct(input); err != nil {
		log.Error(" Invalid TLS cert export input", zap.Error(err))
		return cerr.WithHint(err, "Missing or invalid SCP target input")
	}

	dest := fmt.Sprintf("%s@%s:%s", input.User, input.Host, input.Path)
	log.Info("📤 Exporting Vault TLS cert via SCP", zap.String("source", shared.TLSCrt), zap.String("destination", dest))

	cmd := exec.CommandContext(rc.Ctx, "scp", shared.TLSCrt, dest)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(" SCP command failed", zap.Error(err), zap.ByteString("output", output))
		return cerr.Wrap(err, "scp failed")
	}

	log.Info(" TLS cert exported successfully", zap.ByteString("output", output))
	return nil
}
