// pkg/vault/lifecycle_init.go

package vault

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

/**/
// SetupVault appears to be a logic wrapper for :
// IsAlreadyInitialized
// LoadInitResultOrPrompt
// finalizeVaultSetup
// DumpInitResult

/**/

/**/
func DumpInitResult(initRes *api.InitResponse, log *zap.Logger) {
	b, _ := json.MarshalIndent(initRes, "", "  ")
	_ = os.WriteFile("/tmp/vault_init.json", b, 0600)
	_ = os.WriteFile(DiskPath("vault_init", log), b, 0600)
	fmt.Printf("✅ Vault initialized with %d unseal keys.\n", len(initRes.KeysB64))
}

/**/

/**/
// -> TryLoadUnsealKeysFromFallback() ([]string, error) // ✅
func LoadInitResultOrPrompt(client *api.Client, log *zap.Logger) (*api.InitResponse, error) {
	initResPtr, err := ReadFallbackJSON[api.InitResponse](DiskPath("vault_init", log), log)
	if err != nil {
		log.Warn("Vault fallback read failed", zap.Error(err))
		return PromptForInitResult(log)
	}
	return initResPtr, nil
}

/**/

/**/
// TODO:
func PromptToSaveVaultInitData(init VaultInitResponse) error {

}

/**/

/**/
// TODO:
func ConfirmUnsealMaterialSaved(init VaultInitResponse) error {

}

/**/

/**/
// TODO:
func MaybeWriteVaultInitFallback(init VaultInitResponse) error {

}

/**/

/**/
// TODO: is this just a wrapper for SetupVault along with phaseInitAndUnsealVault
//  called when /sys/health returns 501 (not initialised). It simply feeds the flow into your existing SetupVault helper.
func initAndUnseal(c *api.Client, log *zap.Logger) error {
	_, _, err := SetupVault(c, log) // returns (client, initRes, error)
	return err
}

/**/
