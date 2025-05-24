// pkg/vault/export.go

package vault

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	cerr "github.com/cockroachdb/errors"
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
func ExportTLSCert(input TLSExportInput) error {
	log := zap.L()
	ctx := context.Background()

	ctx, span := telemetry.StartSpan(ctx, "vault.ExportTLSCert")
	defer span.End()

	// Validate input using go-playground/validator
	if err := verify.Struct(input); err != nil {
		span.RecordError(err)
		log.Error("❌ Invalid TLS cert export input", zap.Error(err))
		return cerr.WithHint(err, "Missing or invalid SCP target input")
	}

	dest := fmt.Sprintf("%s@%s:%s", input.User, input.Host, input.Path)
	log.Info("📤 Exporting Vault TLS cert via SCP", zap.String("source", shared.TLSCrt), zap.String("destination", dest))

	cmd := exec.CommandContext(ctx, "scp", shared.TLSCrt, dest)
	output, err := cmd.CombinedOutput()
	if err != nil {
		span.RecordError(err)
		log.Error("❌ SCP command failed", zap.Error(err), zap.ByteString("output", output))
		return cerr.Wrap(err, "scp failed")
	}

	log.Info("✅ TLS cert exported successfully", zap.ByteString("output", output))
	return nil
}
