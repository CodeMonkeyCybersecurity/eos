// pkg/macos/homebrew.go
package macos

import (
	"context"
	"os"
	"os/exec"
	"time"

	crerr "github.com/cockroachdb/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_opa"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
)

// EnsureHomebrewInstalled makes sure "brew" is available on macOS.
// It enforces an OPA policy, emits tracing & structured logging,
// and wraps errors with CockroachDB hints.
func EnsureHomebrewInstalled(ctx context.Context) error {
	log := zap.L().Named("homebrew")
	start := time.Now()

	// 1) OPA policy guard
	if err := eos_opa.Enforce(ctx, "macos/ensure_homebrew", nil); err != nil {
		return crerr.Wrapf(err, "policy denied for Homebrew installation")
	}

	// 2) Start an OpenTelemetry span
	ctx, span := telemetry.Start(ctx, "EnsureHomebrewInstalled")
	defer span.End()

	// 3) If already installed, nothing more to do
	if platform.IsCommandAvailable("brew") {
		log.Info("Homebrew already installed")
		span.SetAttributes(attribute.String("status", "already_installed"))
		return nil
	}
	log.Warn("Homebrew not found")
	span.SetAttributes(attribute.String("status", "not_installed"))

	// 4) Prompt user
	if !interaction.PromptYesNo("Homebrew is required. Install now?", true) {
		span.SetAttributes(attribute.String("user_response", "declined"))
		return crerr.New("Homebrew installation was declined by user")
	}
	span.SetAttributes(attribute.String("user_response", "accepted"))

	// 5) Perform the install
	log.Info("Installing Homebrew…")
	if err := runHomebrewInstaller(); err != nil {
		span.RecordError(err)
		span.SetAttributes(attribute.String("status", "install_failed"))
		return crerr.WithHint(
			crerr.Wrap(err, "failed to install Homebrew"),
			"please install manually from https://brew.sh",
		)
	}

	// 6) Success
	log.Info("Homebrew installed successfully")
	span.SetAttributes(attribute.String("status", "installed"))

	// Note: telemetry.TrackCommand is now handled by your `eos.Wrap` wrapper,
	// so we don’t call it here and avoid signature mismatches.
	_ = time.Since(start) // if you need duration for logging only
	return nil
}

// runHomebrewInstaller encapsulates the actual `brew` install command.
func runHomebrewInstaller() error {
	cmd := exec.Command("/bin/bash", "-c",
		`/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
