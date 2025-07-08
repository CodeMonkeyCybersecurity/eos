package update

import (
	"bytes"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	cerr "github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// SecureDelphiCmd rotates Wazuh passwords & restarts services.
var SecureDelphiCmd = &cobra.Command{
	Use:   "delphi",
	Short: "Harden Delphi (Wazuh) by rotating passwords & updating configs",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, _ *cobra.Command, _ []string) (err error) {
		// ensure rc.End sees our err
		defer rc.End(&err)

		// 1) Download the rotation tool
		if err = delphi.RotateWithTool(rc); err != nil {
			return
		}

		// 2) Fetch current Wazuh API password
		rc.Log.Info(" Extracting current Wazuh API password")
		var apiPass string
		if apiPass, err = delphi.ExtractWazuhUserPassword(rc); err != nil {
			err = cerr.Wrapf(err, "extract Wazuh API password")
			return
		}

		// 3) Try primary rotation, else fallback
		out, rotateErr := delphi.RunPrimary(rc, apiPass)
		if rotateErr != nil {
			rc.Log.Warn("Primary rotation failed, falling back", zap.Error(rotateErr))
			var newPass string
			if newPass, err = delphi.RunFallback(rc); err != nil {
				return
			}
			out = bytes.NewBufferString(fmt.Sprintf(
				"The password for user wazuh is %s\n", newPass,
			))
		}

		// 4) Parse secrets & restart services
		secrets := delphi.ParseSecrets(rc, out)
		if err = delphi.RestartServices(rc, []string{
			"filebeat", "wazuh-manager", "wazuh-dashboard", "wazuh-indexer",
		}); err != nil {
			return
		}

		// 5) Store to Vault (non-fatal on failure)
		if storeErr := vault.HandleFallbackOrStore(rc, "delphi", secrets); storeErr != nil {
			rc.Log.Warn("Failed to store secrets in Vault; continuing", zap.Error(storeErr))
		}

		rc.Log.Info(" Delphi hardening complete")
		return
	}),
}
