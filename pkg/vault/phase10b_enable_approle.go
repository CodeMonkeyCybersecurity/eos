// pkg/vault/phase10_create_approle_auth.go

package vault

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"go.opentelemetry.io/otel/attribute"
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
// │         ├── eos_unix.EnsureOwnedDir
// │         └── eos_unix.WriteOwnedFile(role_id, secret_id)
// └── Done

// PhaseEnableAppRole provisions (or re-uses) an AppRole and writes its creds to disk.
func PhaseEnableAppRole(
	ctx context.Context,
	client *api.Client,
	log *zap.Logger,
	opts shared.AppRoleOptions,
) error {
	// 1) Telemetry span
	ctx, span := telemetry.Start(ctx, "vault.phase_enable_approle",
		attribute.String("force_recreate", fmt.Sprint(opts.ForceRecreate)),
		attribute.Bool("refresh_creds", opts.RefreshCreds),
	)
	defer span.End()

	log.Info("🔑 [Phase10b] Setting up Vault AppRole", zap.Any("options", opts))

	// 2) Ensure the auth method is mounted
	if err := EnableAppRoleAuth(client); err != nil {
		log.Error("Failed to enable AppRole auth", zap.Error(err))
		return cerr.Wrapf(err, "enable approle auth")
	}
	log.Info("✅ AppRole auth method is enabled (or already present)")

	// 3) Provision or reuse the role
	roleID, secretID, err := EnsureAppRole(ctx, client, opts)
	if err != nil {
		log.Error("Failed to ensure AppRole credentials", zap.Error(err))
		return cerr.Wrapf(err, "ensure AppRole")
	}
	log.Debug("AppRole credentials obtained",
		zap.String("role_id", roleID), zap.String("secret_id", secretID),
	)

	// 4) Persist them to disk
	if err := WriteAppRoleFiles(ctx, roleID, secretID); err != nil {
		log.Error("Failed to write AppRole credential files", zap.Error(err))
		return cerr.Wrapf(err, "write AppRole files")
	}

	log.Info("✅ AppRole setup complete", zap.String("role_id", roleID))
	return nil
}

// EnableAppRoleFlow enables AppRole authentication method and provisions EOS-specific AppRole credentials.
func EnableAppRoleFlow(
	ctx context.Context,
	client *api.Client,
	log *zap.Logger,
	opts shared.AppRoleOptions,
) error {
	// 1) trace
	ctx, span := telemetry.Start(ctx, "vault.enable_approle_flow")
	defer span.End()

	log.Info("🪪 [Phase10b] Starting AppRole setup", zap.Any("options", opts))

	// 2) mount auth
	if err := EnableAppRoleAuth(client); err != nil {
		log.Error("failed to enable AppRole auth", zap.Error(err))
		return cerr.Wrapf(err, "enable approle auth")
	}

	// 3) provision or reuse
	roleID, secretID, err := EnsureAppRole(ctx, client, opts)
	if err != nil {
		log.Error("failed to ensure AppRole", zap.Error(err))
		return cerr.Wrapf(err, "ensure AppRole")
	}
	log.Debug("AppRole credentials", zap.String("role_id", roleID))

	// 4) persist to disk
	if err := WriteAppRoleFiles(ctx, roleID, secretID); err != nil {
		log.Error("failed to write AppRole files", zap.Error(err))
		return cerr.Wrapf(err, "write AppRole files")
	}

	log.Info("✅ AppRole setup complete", zap.String("role_id", roleID))
	return nil
}
