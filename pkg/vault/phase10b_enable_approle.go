// pkg/vault/phase10_create_approle_auth.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 10. Create AppRole for EOS
//--------------------------------------------------------------------

// EnableAppRoleFlow(client, log, opts)
// ├── EnableAppRoleAuth(client)
// │    └── client.Sys().EnableAuthWithOptions("approle")
// ├── EnsureAppRole(client, log, opts)
// │    ├── os.Stat(RoleIDPath)
// │    ├── vault.refreshAppRoleCreds(client) (optional)
// │    ├── vault.EnableAppRoleAuth(client) (if needed)
// │    ├── client.Logical().Write(shared.RolePath, roleData)
// │    ├── vault.refreshAppRoleCreds(client)
// │    └── vault.WriteAppRoleFiles(roleID, secretID)
// │         ├── system.EnsureOwnedDir
// │         └── system.WriteOwnedFile(role_id, secret_id)
// └── Done

func PhaseEnableAppRole(client *api.Client, log *zap.Logger, opts shared.AppRoleOptions) error {
	zap.L().Info("[Phase10] Setting up Vault AppRole")
	return EnableAppRoleFlow(client, log, opts)
}

// EnableAppRoleFlow enables AppRole authentication method
// and provisions EOS-specific AppRole credentials.
func EnableAppRoleFlow(client *api.Client, log *zap.Logger, opts shared.AppRoleOptions) error {
	zap.L().Info("🪪 [Enable] Starting AppRole setup flow")

	zap.L().Info("📡 Checking if AppRole auth method is enabled")
	if err := EnableAppRoleAuth(client); err != nil {
		return fmt.Errorf("enable approle auth: %w", err)
	}

	zap.L().Info("🔑 Creating or reusing AppRole credentials")
	roleID, secretID, err := EnsureAppRole(client, opts)
	if err != nil {
		return fmt.Errorf("ensure AppRole: %w", err)
	}

	zap.L().Info("✏️ Writing AppRole credentials to disk")
	if err := WriteAppRoleFiles(roleID, secretID); err != nil {
		return fmt.Errorf("write AppRole files: %w", err)
	}

	zap.L().Info("✅ AppRole setup complete", zap.String("role_id", roleID))
	return nil
}
