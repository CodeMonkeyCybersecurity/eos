package macos

import (
	"context"
	"os"
	"os/exec"
	"time"

	crerr "github.com/cockroachdb/errors"
	"go.opentelemetry.io/otel/attribute"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"go.uber.org/zap"
)

func EnsureHomebrewInstalled(ctx context.Context) error {
	log := zap.L()
	start := time.Now()

	ctx, span := telemetry.StartSpan(ctx, "EnsureHomebrewInstalled")
	defer span.End()

	if platform.IsCommandAvailable("brew") {
		log.Info("✅ Homebrew is already installed")
		span.SetAttributes(attribute.String("status", "already_installed"))
		return nil
	}

	log.Warn("❌ Homebrew is not installed")
	span.SetAttributes(attribute.String("status", "not_found"))

	// Prompt user
	ok := interaction.PromptYesNo("Homebrew is not installed. Would you like to install it now?", true)
	if !ok {
		span.SetAttributes(attribute.String("user_response", "declined"))
		telemetry.TrackCommand(ctx, "EnsureHomebrewInstalled", false, time.Since(start).Milliseconds(), map[string]string{
			"result": "user_declined",
		})
		return crerr.New("Homebrew is required but was not installed. Please install it from https://brew.sh")
	}
	span.SetAttributes(attribute.String("user_response", "accepted"))

	log.Info("📦 Installing Homebrew...")

	cmd := exec.Command(
		"/bin/bash", "-c",
		`/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Error("⚠️ Failed to install Homebrew", zap.Error(err))
		span.RecordError(err)
		span.SetAttributes(attribute.String("status", "install_failed"))

		telemetry.TrackCommand(ctx, "EnsureHomebrewInstalled", false, time.Since(start).Milliseconds(), map[string]string{
			"result": "install_failed",
		})
		return crerr.WithHint(
			crerr.Wrap(err, "Homebrew installation failed"),
			"Try manually installing Homebrew from https://brew.sh",
		)
	}

	log.Info("✅ Homebrew installed successfully")
	span.SetAttributes(attribute.String("status", "installed"))

	telemetry.TrackCommand(ctx, "EnsureHomebrewInstalled", true, time.Since(start).Milliseconds(), map[string]string{
		"result": "installed",
	})
	return nil
}
