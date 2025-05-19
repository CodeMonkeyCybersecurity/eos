// cmd/sync/kvm_file.go

package sync

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
)

var (
	sourceVM   string
	sourcePath string
	destVM     string
	destPath   string
)

var SyncKVMFileCmd = &cobra.Command{
	Use:   "kvm-file",
	Short: "Transfer file from one KVM VM to another via the host",
	RunE: func(cmd *cobra.Command, args []string) error {
		timestamp := time.Now().Format("20060102_150405")
		filename := filepath.Base(sourcePath)
		tempDir := "/var/lib/eos/transfer"
		os.MkdirAll(tempDir, 0700)

		intermediate := filepath.Join(tempDir, fmt.Sprintf("%s_from-%s_to-%s_%s", timestamp, sourceVM, destVM, filename))

		// Phase 1: extract
		if err := kvm.CopyOutFromVM(sourceVM, sourcePath, intermediate); err != nil {
			return fmt.Errorf("extract from %s failed: %w", sourceVM, err)
		}

		// Phase 2: inject
		if err := kvm.CopyInToVM(destVM, intermediate, destPath); err != nil {
			return fmt.Errorf("inject to %s failed: %w", destVM, err)
		}

		fmt.Printf("✅ File transferred successfully: %s -> %s\n", sourceVM, destVM)
		return nil
	},
}

func init() {
	SyncKVMFileCmd.Flags().StringVar(&sourceVM, "from-vm", "", "Source VM name")
	SyncKVMFileCmd.Flags().StringVar(&sourcePath, "from-path", "", "Path to file inside source VM")
	SyncKVMFileCmd.Flags().StringVar(&destVM, "to-vm", "", "Destination VM name")
	SyncKVMFileCmd.Flags().StringVar(&destPath, "to-path", "", "Destination path inside destination VM")
	SyncKVMFileCmd.MarkFlagRequired("from-vm")
	SyncKVMFileCmd.MarkFlagRequired("from-path")
	SyncKVMFileCmd.MarkFlagRequired("to-vm")
	SyncKVMFileCmd.MarkFlagRequired("to-path")
}
