// cmd/inspect/vault.go
package inspect

import (
	"errors"
	"fmt"
	"os"
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

var InspectVaultAgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Check status of the Vault Agent running as eos",
	Long: `Checks whether the Vault Agent systemd service is running,
validates the token at /run/eos/.vault-token, and attempts a test query.`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		fmt.Println("🔍 Checking Vault Agent (eos) service status...")

		// 1. Check if systemd service is running
		status := exec.Command("systemctl", "is-active", "--quiet", "vault-agent-eos.service")
		if err := status.Run(); err != nil {
			fmt.Println("❌ Vault Agent service is NOT running.")
		} else {
			fmt.Println("✅ Vault Agent service is active.")
		}

		// 2. Check for the token file
		tokenPath := "/run/eos/.vault-token"
		if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
			fmt.Println("❌ Vault token file not found:", tokenPath)
			return nil
		}
		fmt.Println("✅ Vault token file exists at", tokenPath)

		// 3. Try accessing Vault using the token
		fmt.Println("📦 Running vault kv get secret/hello as eos...")
		cmdTest := exec.Command("sudo", "-u", "eos", "vault", "kv", "get", "-format=json", "secret/hello")
		cmdTest.Env = append(os.Environ(), "VAULT_TOKEN_PATH="+tokenPath)
		out, err := cmdTest.CombinedOutput()
		if err != nil {
			fmt.Println("❌ Vault test query failed:", err)
			fmt.Println(string(out))
		} else {
			fmt.Println("✅ Vault responded successfully:")
			fmt.Println(string(out))
		}

		return nil
	}),
}

func init() {
	InspectVaultCmd.AddCommand(InspectVaultAgentCmd) // nested!
	InspectCmd.AddCommand(InspectVaultCmd)           // top-level
}
