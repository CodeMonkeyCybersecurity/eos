// cmd/inspect/vault.go
package inspect

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/spf13/cobra"
)

var InspectVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Inspect current Vault paths (requires root or hera)",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		if !utils.IsPrivilegedUser() {
			return errors.New("access denied: must be root or the 'hera' user to inspect Vault")
		}

		fmt.Println("🔐 Listing Vault contents under 'secret/eos/'...")

		cmdExec := exec.Command("vault", "kv", "list", "-format=json", "secret/eos")
		output, err := cmdExec.Output()
		if err != nil {
			return fmt.Errorf("could not list Vault contents: %w", err)
		}

		paths := strings.Split(string(output), ",")
		count := 0
		for _, raw := range paths {
			path := strings.Trim(strings.Trim(raw, "\" \n[]"), "/")
			if path != "" {
				fmt.Printf(" - %s\n", "secret/eos/"+path)
				count++
			}
		}

		fmt.Printf("\n✅ %d entries found.\n", count)
		return nil
	}),
}

func init() {
	InspectCmd.AddCommand(InspectVaultCmd)
}
