// cmd/update/secrets.go

package update

import (
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DEPRECATED: VaultUpdateCmd removed - vault package updates are deprecated
// Use the new port configuration command: eos update vault --ports FROM -> TO
// For package updates, use: eos create vault
