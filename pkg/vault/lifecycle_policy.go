// pkg/vault/lifecycle_policy.go

package vault

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//
// ========================== ENSURE ==========================
//

//
// ========================== LIST ==========================
//

//
// ========================== READ ==========================
//

//
// ========================== UPDATE ==========================
//

//
// ========================== DELETE ==========================
//

func EnsureAgentConfig(vaultAddr string, log *zap.Logger) error {

	// ✅ Check for existing config first
	if _, err := os.Stat(VaultAgentConfigPath); err == nil {
		log.Info("✅ Vault Agent config already exists — skipping rewrite", zap.String("path", VaultAgentConfigPath))
		return nil
	}

	// ✅ Check AppRole files exist
	if _, err := os.Stat(FallbackRoleIDPath); err != nil {
		return fmt.Errorf("role_id not found: %w", err)
	}
	if _, err := os.Stat(FallbackSecretIDPath); err != nil {
		return fmt.Errorf("secret_id not found: %w", err)
	}

	log.Info("✍️ Writing Vault Agent config file", zap.String("path", VaultAgentConfigPath))

	// Use dynamic Vault address and listener
	content := fmt.Sprintf(`
pid_file = "%s"

auto_auth {
  method "approle" {
    config = {
      role_id_file_path   = "%s"
      secret_id_file_path = "%s"
    }
  }
  sink "file" {
    config = {
      path = "%s"
    }
  }
}

vault {
  address = "%s"
}

listener "tcp" {
  address     = "%s"
  tls_disable = true
}

cache {
  use_auto_auth_token = true
}`, AgentPID, FallbackRoleIDPath, FallbackSecretIDPath, VaultAgentTokenPath, vaultAddr, VaultDefaultPort)

	if err := os.WriteFile(VaultAgentConfigPath, []byte(strings.TrimSpace(content)+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write Vault Agent config to %s: %w", VaultAgentConfigPath, err)
	}

	log.Info("✅ Vault Agent config written successfully", zap.String("path", VaultAgentConfigPath))
	return nil
}

// ApplyAdminPolicy applies a full-access policy from the Policies map to the eos user.
func ApplyAdminPolicy(creds UserpassCreds, client *api.Client, log *zap.Logger) error {
	fmt.Println("Creating full-access policy for eos.")

	policyName := EosVaultPolicy
	policy, ok := Policies[policyName]
	if !ok {
		return fmt.Errorf("policy %q not found in Policies map", policyName)
	}

	// Apply policy using the Vault API.
	if err := client.Sys().PutPolicy(policyName, policy); err != nil {
		log.Error("Failed to apply policy via API", zap.Error(err))
		return err
	}
	log.Info("✅ Custom policy applied via API", zap.String("policy", policyName))

	// Update the eos user with the policy.
	_, err := client.Logical().Write(EosVaultUserPath, map[string]interface{}{
		"password": creds.Password,
		"policies": policyName,
	})
	if err != nil {
		log.Error("Failed to update eos user with policy", zap.Error(err))
		return err
	}
	log.Info("✅ eos user updated with full privileges", zap.String("policy", policyName))
	return nil
}
