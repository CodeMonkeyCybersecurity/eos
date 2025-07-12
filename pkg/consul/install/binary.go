// Package install provides Consul installation utilities
package install

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Binary installs the Consul binary from HashiCorp releases.
// It follows the Assess → Intervene → Evaluate pattern.
func Binary(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if Consul is already installed
	if err := execute.RunSimple(rc.Ctx, "which", "consul"); err == nil {
		log.Info("Consul binary already installed, checking version")
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "consul",
			Args:    []string{"version"},
			Capture: true,
		})
		if err == nil {
			log.Info("Current Consul version", zap.String("version", strings.TrimSpace(output)))
			return nil
		}
	}

	log.Info("Installing Consul binary")

	// INTERVENE - Download and install
	// Detect architecture
	arch := eos_unix.GetArchitecture()
	consulVersion := "1.17.1"

	log.Info("Downloading Consul",
		zap.String("version", consulVersion),
		zap.String("architecture", arch))

	steps := []execute.Options{
		{
			Command: "wget",
			Args: []string{
				"-O", "/tmp/consul.zip",
				fmt.Sprintf("https://releases.hashicorp.com/consul/%s/consul_%s_linux_%s.zip",
					consulVersion, consulVersion, arch),
			},
		},
		{Command: "unzip", Args: []string{"-o", "/tmp/consul.zip", "-d", "/tmp/"}},
		{Command: "chmod", Args: []string{"+x", "/tmp/consul"}},
		{Command: "mv", Args: []string{"/tmp/consul", "/usr/local/bin/consul"}},
		{Command: "rm", Args: []string{"-f", "/tmp/consul.zip"}},
	}

	for i, step := range steps {
		log.Debug("Executing installation step",
			zap.Int("step", i+1),
			zap.String("command", step.Command))

		if _, err := execute.Run(rc.Ctx, step); err != nil {
			return fmt.Errorf("installation step %d failed: %w", i+1, err)
		}
	}

	// EVALUATE - Verify installation
	if err := execute.RunSimple(rc.Ctx, "consul", "version"); err != nil {
		return fmt.Errorf("consul verification failed: %w", err)
	}

	log.Info("Consul binary installed successfully")
	return nil
}
