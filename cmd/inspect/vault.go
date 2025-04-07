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
	"go.uber.org/zap"
)

var InspectVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Inspect current Vault paths (requires root or eos)",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := zap.L()

		if !utils.IsPrivilegedUser() {
			log.Error("Access denied: must be root or the 'eos' user to inspect Vault")
			return errors.New("access denied: must be root or the 'eos' user to inspect Vault")
		}

		log.Info("Querying Vault for secrets under path", zap.String("path", "secret/eos/"))
		cmdExec := exec.Command("vault", "kv", "list", "-format=json", "secret/eos")
		output, err := cmdExec.Output()
		if err != nil {
			log.Error("Failed to list Vault secrets", zap.Error(err))
			return fmt.Errorf("could not list Vault contents: %w", err)
		}

		rawOutput := string(output)
		log.Debug("Raw Vault output", zap.String("output", rawOutput))

		paths := strings.Split(rawOutput, ",")
		count := 0
		for _, raw := range paths {
			path := strings.Trim(strings.Trim(raw, "\" \n[]"), "/")
			if path != "" {
				secretPath := "secret/eos/" + path
				log.Info("Found Vault entry", zap.String("path", secretPath))
				fmt.Printf(" - %s\n", secretPath)
				count++
			}
		}

		log.Info("Vault secret list complete", zap.Int("count", count))
		fmt.Printf("\n✅ %d entries found.\n", count)
		return nil
	}),
}

func init() {
	InspectCmd.AddCommand(InspectVaultCmd)
}
