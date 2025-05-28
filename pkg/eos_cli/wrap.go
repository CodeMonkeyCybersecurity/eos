// pkg/eos_cli/wrap.go

package eos_cli

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
)

type RunE func(*eos_io.RuntimeContext, *cobra.Command, []string) error

func Wrap(fn RunE) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) (err error) {
		// Init telemetry early, fail gracefully
		if initErr := telemetry.Init(); initErr != nil {
			fmt.Fprintf(os.Stderr, "⚠️ Telemetry disabled: %v\n", initErr)
		}

		rc := eos_io.NewContext(cmd.Name())
		defer rc.HandlePanic(&err)
		defer rc.End(&err)

		// Vault context
		vaultAddr, vaultErr := vault.EnsureVaultEnv()
		rc.Attributes["vault_addr"] = eos_io.LogVaultContext(rc.Log, vaultAddr, vaultErr)

		// Optional validation — runs only if WrapValidation was set
		if rc.Validation != nil {
			if err := rc.ValidateAll(); err != nil {
				return err
			}
		}

		// Run the actual command logic
		err = fn(rc, cmd, args)
		return err
	}
}
