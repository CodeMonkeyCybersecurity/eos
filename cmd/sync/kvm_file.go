// cmd/sync/kvm_file.go

package sync

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	sourceVM   string
	sourcePath string
	destVM     string
	destPath   string
)

var SyncKVMFileCmd = &cobra.Command{
	Use:   "kvm-file",
	Short: "Transfer a file from one KVM VM to another via the host",
	Long: `Extracts a file from a source KVM virtual machine,
stores it temporarily on the host with a timestamped filename,
then injects it into a destination VM.

Both VMs must be shut off for virt-copy to work.`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		timestamp := time.Now().Format("20060102_150405")
		filename := filepath.Base(sourcePath)
		tempDir := "/var/lib/eos/transfer"
		if err := os.MkdirAll(tempDir, 0700); err != nil {
			return fmt.Errorf("failed to create temp dir: %w", err)
		}

		intermediate := filepath.Join(tempDir, fmt.Sprintf("%s_from-%s_to-%s_%s", timestamp, sourceVM, destVM, filename))
		ctx.Log.Info("📤 Starting KVM file sync",
			zap.String("sourceVM", sourceVM),
			zap.String("sourcePath", sourcePath),
			zap.String("destVM", destVM),
			zap.String("destPath", destPath),
			zap.String("hostTempFile", intermediate),
		)

		if err := kvm.CopyOutFromVM(sourceVM, sourcePath, intermediate); err != nil {
			return fmt.Errorf("extract from %s failed: %w", sourceVM, err)
		}

		if err := kvm.CopyInToVM(destVM, intermediate, destPath); err != nil {
			return fmt.Errorf("inject to %s failed: %w", destVM, err)
		}

		ctx.Log.Info("✅ File transferred successfully", zap.String("from", sourceVM), zap.String("to", destVM))
		return nil
	}),
}

func init() {
	SyncCmd.AddCommand(SyncKVMFileCmd)

	SyncKVMFileCmd.Flags().StringVar(&sourceVM, "from-vm", "", "Source VM name")
	SyncKVMFileCmd.Flags().StringVar(&sourcePath, "from-path", "", "Path to file inside source VM")
	SyncKVMFileCmd.Flags().StringVar(&destVM, "to-vm", "", "Destination VM name")
	SyncKVMFileCmd.Flags().StringVar(&destPath, "to-path", "", "Destination path inside destination VM")
	SyncKVMFileCmd.MarkFlagRequired("from-vm")
	SyncKVMFileCmd.MarkFlagRequired("from-path")
	SyncKVMFileCmd.MarkFlagRequired("to-vm")
	SyncKVMFileCmd.MarkFlagRequired("to-path")
}
