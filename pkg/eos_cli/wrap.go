// pkg/eos_cli/wrap.go

package eos_cli

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
)

type RunE func(*eos_io.RuntimeContext, *cobra.Command, []string) error

func Wrap(fn RunE) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) (err error) {
		rc := eos_io.NewContext(cmd.Name())
		defer rc.HandlePanic(&err)
		defer rc.End(&err)

		// 1) Vault lookup
		vaultAddr, vaultErr := vault.EnsureVaultEnv()
		rc.Attributes["vault_addr"] = eos_io.LogVaultContext(rc.Log, vaultAddr, vaultErr)

		// 2) Validation
		if err = rc.ValidateAll(); err != nil {
			return err
		}

		// 3) Execute
		err = fn(rc, cmd, args)
		return err
	}
}
