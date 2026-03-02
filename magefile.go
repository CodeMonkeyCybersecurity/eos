//go:build mage

package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/magefile/mage/mg"
)

// Ci contains CI-oriented Mage targets.
type Ci mg.Namespace

// Debug runs the local CI parity lane used by pre-commit and CI workflows.
func (Ci) Debug() error {
	return runNpmScript("ci:debug", "bash", "scripts/ci/debug.sh")
}

// SelfUpdateQuality runs the self-update focused quality lane.
func (Ci) SelfUpdateQuality() error {
	return runNpmScript("ci:self-update-quality", "bash", "scripts/ci/self-update-quality.sh")
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %v: %w", name, args, err)
	}
	return nil
}

func runNpmScript(script, fallbackName string, fallbackArgs ...string) error {
	if _, err := exec.LookPath("npm"); err == nil {
		if err := run("npm", "run", script, "--silent"); err == nil {
			return nil
		}
	}
	return run(fallbackName, fallbackArgs...)
}
