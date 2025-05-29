// pkg/macos/homebrew.go
package macos

import (
	"os"
	"os/exec"
	"time"

	crerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_opa"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
)

// EnsureHomebrewInstalled makes sure "brew" is available on macOS.
// It enforces an OPA policy, emits tracing & structured logging,
// and wraps errors with CockroachDB hints.
func EnsureHomebrewInstalled(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	start := time.Now()

	// 1) OPA policy guard
	if err := eos_opa.Enforce(rc.Ctx, "macos/ensure_homebrew", nil); err != nil {
		return crerr.Wrapf(err, "policy denied for Homebrew installation")
	}

	// 3) If already installed, nothing more to do
	if platform.IsCommandAvailable("brew") {
		log.Info("Homebrew already installed")
		return nil
	}
	log.Warn("Homebrew not found")

	// 4) Prompt user
	if !interaction.PromptYesNo(rc.Ctx, "Homebrew is required. Install now?", true) {
		return crerr.New("Homebrew installation was declined by user")
	}

	// 5) Perform the install
	log.Info("Installing Homebrew…")
	if err := runHomebrewInstaller(); err != nil {
		return crerr.WithHint(
			crerr.Wrap(err, "failed to install Homebrew"),
			"please install manually from https://brew.sh",
		)
	}

	// 6) Success
	log.Info("Homebrew installed successfully")

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
