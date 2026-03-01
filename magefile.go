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
	return run("bash", "scripts/ci/debug.sh")
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
