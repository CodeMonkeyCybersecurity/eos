// pkg/vault/auth_userpass.go
package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api/auth/userpass"
	"go.uber.org/zap"
)

// EnableVaultUserpass sets up userpass auth, creates the "eos" user, and verifies login.
func EnableVaultUserpass(rc *eos_io.RuntimeContext) error {
	// 1) Build a Vault API client
	client, err := NewClient(rc)
	if err != nil {
		return cerr.Wrap(err, "create Vault client")
	}

	// 2) Enable the userpass & approle auth mounts
	if err := EnableUserpassAuth(rc, client); err != nil {
		return cerr.Wrap(err, "enable userpass auth")
	}
	if err := EnableAppRoleAuth(rc, client); err != nil {
		return cerr.Wrap(err, "enable approle auth")
	}
	rc.Log.Info(" Auth methods enabled")

	// 3) Ensure the Eos policy exists
	if err := EnsurePolicy(rc); err != nil {
		return cerr.Wrap(err, "ensure Eos policy")
	}
	rc.Log.Info(" Eos policy ensured")

	// 4) Prompt for the Eos user’s password
	pass, err := crypto.PromptPassword(rc, "Enter password for Vault 'eos' user: ")
	if err != nil {
		return cerr.Wrap(err, "prompt Eos password")
	}
	rc.Log.Info(" Password captured")

	// 5) Create the 'eos' user under userpass
	writePath := "auth/userpass/users/eos"
	data := map[string]interface{}{
		"password": pass,
		"policies": shared.EosDefaultPolicyName,
	}
	if _, err := client.Logical().Write(writePath, data); err != nil {
		return cerr.Wrapf(err, "create Eos Vault user at %s", writePath)
	}
	rc.Log.Info(" Eos user created", zap.String("path", writePath))

	// 6) Validate by logging in as that user
	upAuth, err := userpass.NewUserpassAuth(
		"eos",
		&userpass.Password{FromString: pass},
		userpass.WithMountPath("userpass"),
	)
	if err != nil {
		return cerr.Wrap(err, "create UserpassAuth object")
	}

	secret, err := upAuth.Login(rc.Ctx, client)
	if err != nil {
		return cerr.Wrap(err, "login as Eos user failed")
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("login response missing auth data")
	}

	// Shorten the token for logging
	tok := secret.Auth.ClientToken
	if len(tok) > 8 {
		tok = tok[:8] + "…"
	}
	rc.Log.Info(" Authenticated with Eos Vault user", zap.String("token", tok))

	return nil
}
