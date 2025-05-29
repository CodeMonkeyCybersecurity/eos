// pkg/vault/phase_init.go

package vault

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfirmIrreversibleDeletion gets final consent before wiping unseal material.
func ConfirmIrreversibleDeletion(rc *eos_io.RuntimeContext) error {
	fmt.Println("⚠️ Confirm irreversible deletion of unseal materials. This action is final.")
	fmt.Print("Type 'yes' to proceed: ")

	reader := bufio.NewReader(os.Stdin)
	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(strings.ToLower(resp))
	if resp != "yes" {
		return fmt.Errorf("user aborted deletion confirmation")
	}
	otelzap.Ctx(rc.Ctx).Info("🧹 User confirmed deletion of in-memory secrets")
	return nil
}

func DeleteTestDataFromDisk(rc *eos_io.RuntimeContext) error {
	path := filepath.Join(shared.SecretsDir, shared.TestDataFilename)
	if err := os.Remove(path); err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to delete fallback test-data file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("delete fallback test-data file: %w", err)
	}

	fmt.Println()
	fmt.Println("🗑️  Test Data Deletion Summary")
	fmt.Println("  💾 Disk: SUCCESS")
	fmt.Printf("    📂 Path: %s\n\n", path)
	otelzap.Ctx(rc.Ctx).Info("✅ Test-data deleted successfully (fallback)", zap.String("path", path))
	return nil
}
