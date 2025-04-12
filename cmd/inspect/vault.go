// cmd/inspect/vault.go
package inspect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consts"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ldap"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var InspectVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Inspect current Vault paths (requires root or eos)",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := zap.L().Named("inspect").With(zap.String("component", "vault"))

		if !utils.IsPrivilegedUser() {
			log.Error("Access denied", zap.String("action", "permission-check"), zap.String("status", "denied"))
			fmt.Println(`❌ Access denied. You must be root or the 'eos' user.

✅ Try again with:
   sudo eos inspect vault`)
			return fmt.Errorf("requires root or eos user")
		}

		if _, err := exec.LookPath("vault"); err != nil {
			log.Error("Vault CLI not found", zap.String("action", "lookup"), zap.String("status", "missing"))
			fmt.Println(`❌ HashiCorp Vault CLI not found in $PATH

💡 You can install it with:
   sudo apt install vault

Or verify it's available to the current user:
   which vault
   echo $PATH`)
			return fmt.Errorf("vault CLI binary not found")
		}

		log.Info("Listing secrets in Vault", zap.String("action", "list"), zap.String("path", "secret/eos/"))

		cmdExec := exec.Command("vault", "kv", "list", "-format=json", "secret/eos")
		output, err := cmdExec.Output()
		if err != nil {
			log.Error("Vault list failed", zap.String("action", "list"), zap.Error(err))
			return fmt.Errorf("could not list Vault contents: %w", err)
		}

		paths := strings.Split(string(output), ",")
		count := 0
		for _, raw := range paths {
			entry := strings.Trim(strings.Trim(raw, "\" \n[]"), "/")
			if entry != "" {
				fullPath := "secret/eos/" + entry
				log.Info("Found Vault entry", zap.String("path", fullPath))
				fmt.Printf(" - %s\n", fullPath)
				count++
			}
		}

		log.Info("Vault secrets query complete", zap.String("action", "list"), zap.String("status", "success"), zap.Int("count", count))
		fmt.Printf("\n✅ %d entries found.\n", count)
		return nil
	}),
}

// cmd/inspect/vault.go (continuation)

var InspectVaultAgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Check status of the Vault Agent running as eos",
	Long: `Checks whether the Vault Agent systemd service is running,
validates the token at /run/eos/.vault-token, and attempts a test query.`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := zap.L().Named("vault-agent").With(zap.String("component", "vault-agent"))

		fmt.Println("🔍 Checking Vault Agent (eos) service status...")
		log.Info("Checking systemd service", zap.String("action", "check-systemd"))

		status := exec.Command("systemctl", "is-active", "--quiet", "vault-agent-eos.service")
		if err := status.Run(); err != nil {
			fmt.Println("❌ Vault Agent service is NOT running.")
			log.Warn("Vault Agent service inactive", zap.String("status", "inactive"))
		} else {
			fmt.Println("✅ Vault Agent service is active.")
			log.Info("Vault Agent service is running", zap.String("status", "active"))
		}

		tokenPath := "/run/eos/.vault-token"
		log.Info("Checking for Vault token file", zap.String("action", "check-token"), zap.String("path", tokenPath))

		if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
			fmt.Println("❌ Vault token file not found:", tokenPath)
			log.Error("Vault token missing", zap.String("status", "missing"))
			return nil
		}
		fmt.Println("✅ Vault token file exists at", tokenPath)
		log.Info("Vault token found", zap.String("status", "exists"))

		fmt.Println("📦 Running vault kv get secret/hello as eos...")
		log.Info("Attempting test query", zap.String("action", "query"))

		cmdTest := exec.Command("sudo", "-u", "eos", "vault", "kv", "get", "-format=json", "secret/hello")
		cmdTest.Env = append(os.Environ(), "VAULT_TOKEN_PATH="+tokenPath)
		out, err := cmdTest.CombinedOutput()
		if err != nil {
			fmt.Println("❌ Vault test query failed:", err)
			fmt.Println(string(out))
			log.Error("Vault test query failed", zap.String("output", string(out)), zap.Error(err))
		} else {
			fmt.Println("✅ Vault responded successfully:")
			fmt.Println(string(out))
			log.Info("Vault test query succeeded", zap.String("status", "success"))
		}

		return nil
	}),
}

var InspectVaultLDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "View stored LDAP config in Vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := &ldap.LDAPConfig{}
		err := vault.ReadFromVaultAt(context.Background(), consts.LDAPVaultMount, consts.LDAPVaultPath, cfg)
		if err != nil {
			return fmt.Errorf("could not load LDAP config from Vault: %w", err)
		}
		fmt.Println("✅ LDAP config from Vault:")
		fmt.Printf("  FQDN:         %s\n", cfg.FQDN)
		fmt.Printf("  BindDN:       %s\n", cfg.BindDN)
		fmt.Printf("  UserBase:     %s\n", cfg.UserBase)
		fmt.Printf("  RoleBase:     %s\n", cfg.RoleBase)
		fmt.Printf("  AdminRole:    %s\n", cfg.AdminRole)
		fmt.Printf("  ReadonlyRole: %s\n", cfg.ReadonlyRole)
		fmt.Printf("  Password:     %s\n", crypto.Redact(cfg.Password))
		return nil
	},
}

func init() {
	InspectVaultCmd.AddCommand(InspectVaultAgentCmd) // nested command
	InspectCmd.AddCommand(InspectVaultCmd)           // top-level command
	InspectVaultCmd.AddCommand(InspectVaultLDAPCmd)
}
