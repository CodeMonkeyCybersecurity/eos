// cmd/sync/kvm_file.go

package update

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var SyncKVMFileCmd = &cobra.Command{
	Use:   "kvm-file",
	Short: "Transfer a file from one KVM VM to another via the host",
	Long: `Extracts a file from a source KVM virtual machine,
stores it temporarily on the host with a timestamped filename,
then injects it into a destination VM.

Both VMs must be shut off for virt-copy to work.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		timestamp := time.Now().Format("20060102_150405")
		filename := filepath.Base(kvm.SourcePath)
		tempDir := "/var/lib/eos/transfer"
		if err := os.MkdirAll(tempDir, 0700); err != nil {
			return fmt.Errorf("failed to create temp dir: %w", err)
		}

		intermediate := filepath.Join(tempDir, fmt.Sprintf("%s_from-%s_to-%s_%s", timestamp, kvm.SourceVM, kvm.DestVM, filename))
		rc.Log.Info(" Starting KVM file sync",
			zap.String("sourceVM", kvm.SourceVM),
			zap.String("sourcePath", kvm.SourcePath),
			zap.String("destVM", kvm.DestVM),
			zap.String("destPath", kvm.DestPath),
			zap.String("hostTempFile", intermediate),
		)

		err := kvm.SyncFileBetweenVMs(rc, kvm.SourceVM, kvm.SourcePath, kvm.DestVM, kvm.DestPath)
		if err != nil {
			log.Fatal("sync failed", zap.Error(err))
		}

		rc.Log.Info(" File transferred successfully", zap.String("from", kvm.SourceVM), zap.String("to", kvm.DestVM))
		return nil
	}),
}

func init() {
	UpdateCmd.AddCommand(SyncKVMFileCmd)

	SyncKVMFileCmd.Flags().StringVar(&kvm.SourceVM, "from-vm", "", "Source VM name")
	SyncKVMFileCmd.Flags().StringVar(&kvm.SourcePath, "from-path", "", "Path to file inside source VM")
	SyncKVMFileCmd.Flags().StringVar(&kvm.DestVM, "to-vm", "", "Destination VM name")
	SyncKVMFileCmd.Flags().StringVar(&kvm.DestPath, "to-path", "", "Destination path inside destination VM")
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}

	must(SyncKVMFileCmd.MarkFlagRequired("from-vm"))
	must(SyncKVMFileCmd.MarkFlagRequired("from-path"))
	must(SyncKVMFileCmd.MarkFlagRequired("to-vm"))
	must(SyncKVMFileCmd.MarkFlagRequired("to-path"))
}
