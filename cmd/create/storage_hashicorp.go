package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/hashicorp"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var StorageHashiCorpCmd = &cobra.Command{
	Use:   "storage-hashicorp",
	Short: "Create and manage storage using HashiCorp stack",
	Long: `Create and manage storage volumes using HashiCorp Nomad, Consul, and Vault.
This command integrates with CSI plugins to provide dynamic storage provisioning.`,
	RunE: eos_cli.Wrap(runCreateStorageHashiCorp),
}

var (
	storageSize     string
	storageProvider string
	storagePluginID string
	encrypted       bool
	namespace       string
)

func init() {
	StorageHashiCorpCmd.Flags().StringVar(&storageSize, "size", "10Gi", "Storage volume size")
	StorageHashiCorpCmd.Flags().StringVar(&storageProvider, "provider", "aws-ebs", "Storage provider (aws-ebs, gcp-pd, azure-disk)")
	StorageHashiCorpCmd.Flags().StringVar(&storagePluginID, "plugin-id", "aws-ebs0", "CSI plugin ID")
	StorageHashiCorpCmd.Flags().BoolVar(&encrypted, "encrypted", true, "Enable encryption")
	StorageHashiCorpCmd.Flags().StringVar(&namespace, "namespace", "default", "Storage namespace")
}

func runCreateStorageHashiCorp(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("volume name is required")
	}

	volumeName := args[0]
	volumeID := fmt.Sprintf("%s-%s", namespace, volumeName)

	otelzap.Ctx(rc.Ctx).Info("Creating HashiCorp storage volume",
		zap.String("name", volumeName),
		zap.String("id", volumeID),
		zap.String("size", storageSize),
		zap.String("provider", storageProvider))

	// Parse size to bytes
	sizeBytes, err := parseStorageSize(storageSize)
	if err != nil {
		return fmt.Errorf("invalid storage size: %w", err)
	}

	// Initialize HashiCorp storage manager
	manager, err := hashicorp.NewHashiCorpStorageManager(
		rc,
		"http://localhost:4646", // Nomad
		"http://localhost:8500", // Consul
		fmt.Sprintf("http://localhost:%d", shared.PortVault), // Vault
	)
	if err != nil {
		return fmt.Errorf("failed to initialize storage manager: %w", err)
	}

	// Health check
	if err := manager.HealthCheck(rc.Ctx); err != nil {
		return fmt.Errorf("HashiCorp stack health check failed: %w", err)
	}

	// Create volume request
	req := &hashicorp.VolumeRequest{
		ID:        volumeID,
		Name:      volumeName,
		SizeBytes: sizeBytes,
		PluginID:  storagePluginID,
		Provider:  storageProvider,
		Encrypted: encrypted,
		Namespace: namespace,
		Metadata: map[string]string{
			"created-by": "eos-cli",
			"namespace":  namespace,
			"provider":   storageProvider,
		},
	}

	// Create the volume
	volume, err := manager.CreateVolume(rc.Ctx, req)
	if err != nil {
		return fmt.Errorf("failed to create volume: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info("Storage volume created successfully",
		zap.String("id", volume.ID),
		zap.String("name", volume.Name),
		zap.Int64("size", volume.Size),
		zap.String("status", volume.Status))

	fmt.Printf(" Storage volume created:\n")
	fmt.Printf("   ID: %s\n", volume.ID)
	fmt.Printf("   Name: %s\n", volume.Name)
	fmt.Printf("   Size: %s\n", formatBytes(volume.Size))
	fmt.Printf("   Provider: %s\n", volume.Provider)
	fmt.Printf("   Status: %s\n", volume.Status)

	return nil
}

func parseStorageSize(size string) (int64, error) {
	// Simple parser for common storage sizes
	switch {
	case len(size) >= 2 && size[len(size)-2:] == "Gi":
		var gb int64
		if _, err := fmt.Sscanf(size, "%dGi", &gb); err != nil {
			return 0, err
		}
		return gb * 1024 * 1024 * 1024, nil
	case len(size) >= 2 && size[len(size)-2:] == "Mi":
		var mb int64
		if _, err := fmt.Sscanf(size, "%dMi", &mb); err != nil {
			return 0, err
		}
		return mb * 1024 * 1024, nil
	case len(size) >= 2 && size[len(size)-2:] == "Ti":
		var tb int64
		if _, err := fmt.Sscanf(size, "%dTi", &tb); err != nil {
			return 0, err
		}
		return tb * 1024 * 1024 * 1024 * 1024, nil
	default:
		return 0, fmt.Errorf("unsupported size format: %s (use Gi, Mi, or Ti)", size)
	}
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
