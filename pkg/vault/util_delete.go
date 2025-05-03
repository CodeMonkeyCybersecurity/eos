// pkg/vault/phase_init.go

package vault

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
)

// ConfirmIrreversibleDeletion gets final consent before wiping unseal material.
func ConfirmIrreversibleDeletion() error {
	fmt.Println("⚠️ Confirm irreversible deletion of unseal materials. This action is final.")
	fmt.Print("Type 'yes' to proceed: ")

	reader := bufio.NewReader(os.Stdin)
	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(strings.ToLower(resp))
	if resp != "yes" {
		return fmt.Errorf("user aborted deletion confirmation")
	}
	zap.L().Info("🧹 User confirmed deletion of in-memory secrets")
	return nil
}
