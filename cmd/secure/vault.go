// cmd/secure/vault.go

package secure

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var SecureVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Secures Vault by revoking the root token and elevating admin privileges",
	Long: `This command secures your Vault setup after "github.com/CodeMonkeyCybersecurity/eos enable vault" has been run.
It reads the stored initialization data (vault_init.json), prompts you to confirm that you have securely 
distributed the unseal keys and root token, then revokes the root token and updates the admin user to have
full (root-level) privileges. Finally, it deletes the stored initialization file.
Please follow up by configuring MFA via your organization's preferred integration method.`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {

		vault.SetVaultEnv()

		client, err := vault.NewClient()
		if err != nil {
			log.Fatal("Failed to create Vault client", zap.Error(err))
		}

		initRes, creds, storedHashes, hashedRoot := vault.LoadVaultSecureData(client)
		vault.CheckVaultSecrets(storedHashes, hashedRoot)
		applyAdminPolicy(creds)

		vault.RevokeRootToken(client, initRes.RootToken)
		platform.CleanupFile("vault_init.json")
		vault.PrintNextSteps()
		return nil
	}),
}

func applyAdminPolicy(creds vault.UserpassCreds) {
	const (
		policyName    = "admin-full"
		policyPath    = "/tmp/admin-full.hcl"
		policyContent = `
path "*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}`
	)

	fmt.Println("Creating full-access policy for admin...")

	// Write the policy file to disk
	if err := os.WriteFile(policyPath, []byte(policyContent), 0600); err != nil {
		log.Fatal("Failed to write policy file", zap.Error(err))
	}
	defer func() {
		if err := os.Remove(policyPath); err != nil {
			log.Warn("Failed to delete temp policy file", zap.Error(err))
		} else {
			fmt.Println("Temporary policy file deleted.")
		}
	}()

	// Apply policy to Vault
	if err := runVaultCmd("policy", "write", policyName, policyPath); err != nil {
		log.Fatal("Failed to apply policy to Vault", zap.Error(err))
	}
	fmt.Println("✅ Custom policy applied to Vault.")

	// Attach policy to admin user
	err := runVaultCmd("write",
		"auth/userpass/users/admin",
		"policies="+policyName,
		fmt.Sprintf("password=%s", creds.Password),
	)
	if err != nil {
		log.Fatal("Failed to update admin user with policy", zap.Error(err))
	}
	fmt.Println("✅ Admin user updated with full privileges.")
}

func runVaultCmd(args ...string) error {
	cmd := exec.Command("vault", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ Vault command failed: %s\n%s\n", strings.Join(args, " "), string(output))
	}
	return err
}

func init() {
	SecureCmd.AddCommand(SecureVaultCmd)
}
