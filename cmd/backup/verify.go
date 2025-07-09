// cmd/backup/verify.go

package backup

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify backup integrity",
	Long: `Verify the integrity of backups and repositories.

Examples:
  # Verify repository integrity
  eos backup verify repository --repo local
  
  # Verify specific snapshot
  eos backup verify snapshot abc123def
  
  # Verify with data verification (slower but thorough)
  eos backup verify repository --repo remote --read-data`,
}

var verifyRepoCmd = &cobra.Command{
	Use:   "repository",
	Short: "Verify repository integrity",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		repoName, _ := cmd.Flags().GetString("repo")
		readData, _ := cmd.Flags().GetBool("read-data")
		readDataSubset, _ := cmd.Flags().GetString("read-data-subset")

		// Use default repository if not specified
		if repoName == "" {
			config, err := backup.LoadConfig(rc)
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}
			repoName = config.DefaultRepository
			if repoName == "" {
				return fmt.Errorf("no repository specified and no default configured")
			}
		}

		logger.Info("Verifying repository integrity",
			zap.String("repository", repoName),
			zap.Bool("read_data", readData),
			zap.String("read_data_subset", readDataSubset))

		// Create backup client
		client, err := backup.NewClient(rc, repoName)
		if err != nil {
			return fmt.Errorf("creating backup client: %w", err)
		}

		// Build check command
		checkArgs := []string{"check"}
		
		if readData {
			checkArgs = append(checkArgs, "--read-data")
		} else if readDataSubset != "" {
			checkArgs = append(checkArgs, "--read-data-subset", readDataSubset)
		}

		// Run verification
		logger.Info("Running repository check")
		output, err := client.RunRestic(checkArgs...)
		if err != nil {
			logger.Error("Repository verification failed",
				zap.Error(err),
				zap.String("output", string(output)))
			return fmt.Errorf("repository verification failed: %w", err)
		}

		logger.Info("Repository verification completed successfully",
			zap.String("output", string(output)))

		fmt.Println("Repository verified successfully!")
		if readData || readDataSubset != "" {
			fmt.Println("Data integrity check: PASSED")
		}

		return nil
	}),
}

var verifySnapshotCmd = &cobra.Command{
	Use:   "snapshot <id>",
	Short: "Verify snapshot integrity",
	Args:  cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		snapshotID := args[0]
		repoName, _ := cmd.Flags().GetString("repo")
		readData, _ := cmd.Flags().GetBool("read-data")

		// Use default repository if not specified
		if repoName == "" {
			config, err := backup.LoadConfig(rc)
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}
			repoName = config.DefaultRepository
			if repoName == "" {
				return fmt.Errorf("no repository specified and no default configured")
			}
		}

		logger.Info("Verifying snapshot integrity",
			zap.String("snapshot", snapshotID),
			zap.String("repository", repoName),
			zap.Bool("read_data", readData))

		// Create backup client
		client, err := backup.NewClient(rc, repoName)
		if err != nil {
			return fmt.Errorf("creating backup client: %w", err)
		}

		// Verify snapshot exists
		snapshots, err := client.ListSnapshots()
		if err != nil {
			return fmt.Errorf("listing snapshots: %w", err)
		}

		found := false
		for _, snap := range snapshots {
			if snap.ID == snapshotID || (snapshotID == "latest" && len(snapshots) > 0) {
				found = true
				if snapshotID == "latest" {
					snapshotID = snap.ID
				}
				break
			}
		}

		if !found {
			return fmt.Errorf("snapshot %q not found", snapshotID)
		}

		// Run verification
		if err := client.Verify(snapshotID); err != nil {
			return fmt.Errorf("snapshot verification failed: %w", err)
		}

		logger.Info("Snapshot verification completed successfully")
		fmt.Printf("Snapshot %s verified successfully!\n", snapshotID)

		return nil
	}),
}

func init() {
	verifyCmd.AddCommand(verifyRepoCmd)
	verifyCmd.AddCommand(verifySnapshotCmd)

	// Repository verify flags
	verifyRepoCmd.Flags().String("repo", "", "Repository to verify")
	verifyRepoCmd.Flags().Bool("read-data", false, "Verify actual data (slower)")
	verifyRepoCmd.Flags().String("read-data-subset", "", "Verify subset of data (e.g., '1/5' checks 20%)")

	// Snapshot verify flags
	verifySnapshotCmd.Flags().String("repo", "", "Repository containing the snapshot")
	verifySnapshotCmd.Flags().Bool("read-data", false, "Verify actual data (slower)")
}
