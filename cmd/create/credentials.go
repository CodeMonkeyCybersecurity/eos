package create

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/database_management"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateCredentialsCmd creates the credentials management command
func CreateCredentialsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "credentials",
		Aliases: []string{"creds"},
		Short:   "Manage dynamic database credentials",
		Long: `Manage dynamic database credentials through Vault.

This command provides credential management functionality:
- Generate new dynamic credentials
- Revoke existing credentials
- List active leases
- Renew credentials

Examples:
  eos database credentials generate --role delphi-readonly
  eos database credentials revoke --lease-id vault:db:123
  eos database credentials list --role delphi-readonly`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			otelzap.Ctx(rc.Ctx).Info("No subcommand provided for credentials command")
			_ = cmd.Help()
			return nil
		}),
	}

	// Add subcommands
	CreateCmd.AddCommand(newGenerateCredentialsCmd())
	CreateCmd.AddCommand(newRevokeCredentialsCmd())

	return cmd
}

func newGenerateCredentialsCmd() *cobra.Command {
	var (
		roleName     string
		engineMount  string
		outputJSON   bool
		showPassword bool
	)

	cmd := &cobra.Command{
		Use:     "generate",
		Aliases: []string{"gen"},
		Short:   "Generate new dynamic database credentials",
		Long: `Generate new dynamic database credentials for a specific role.

Examples:
  eos database credentials generate --role delphi-readonly
  eos database credentials generate --role delphi-readonly --json
  eos database credentials generate --role myapp-user --show-password`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			if roleName == "" {
				return fmt.Errorf("role name is required (use --role)")
			}

			logger.Info("Generating dynamic database credentials", zap.String("role", roleName))

			manager := database_management.NewDatabaseManager()

			options := &database_management.VaultOperationOptions{
				EngineMount: engineMount,
				RoleName:    roleName,
			}

			if options.EngineMount == "" {
				options.EngineMount = "database"
			}

			credential, err := manager.GenerateCredentials(rc, options)
			if err != nil {
				return fmt.Errorf("failed to generate credentials: %w", err)
			}

			if outputJSON {
				return outputJSONCredential(credential, showPassword)
			}

			return outputTableCredential(credential, showPassword)
		}),
	}

	cmd.Flags().StringVarP(&roleName, "role", "r", "", "Database role name")
	cmd.Flags().StringVar(&engineMount, "engine-mount", "database", "Vault database engine mount point")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")
	cmd.Flags().BoolVar(&showPassword, "show-password", false, "Show password in output")

	return cmd
}

func newRevokeCredentialsCmd() *cobra.Command {
	var (
		leaseID string
		force   bool
	)

	cmd := &cobra.Command{
		Use:     "revoke",
		Aliases: []string{"rev"},
		Short:   "Revoke dynamic database credentials",
		Long: `Revoke dynamic database credentials by lease ID.

Examples:
  eos database credentials revoke --lease-id vault:db:123456
  eos database credentials revoke --lease-id vault:db:123456 --force`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			if leaseID == "" {
				return fmt.Errorf("lease ID is required (use --lease-id)")
			}

			logger.Info("Revoking database credentials", zap.String("lease_id", leaseID))

			if !force {
				fmt.Printf("Are you sure you want to revoke lease %s? [y/N]: ", leaseID)
				var response string
				if _, err := fmt.Scanln(&response); err != nil {
					logger.Warn("Failed to read user input", zap.Error(err))
					return fmt.Errorf("failed to read confirmation: %w", err)
				}
				if response != "y" && response != "Y" {
					logger.Info("Revocation cancelled")
					return nil
				}
			}

			manager := database_management.NewDatabaseManager()

			if err := manager.RevokeCredentials(rc, leaseID); err != nil {
				return fmt.Errorf("failed to revoke credentials: %w", err)
			}

			logger.Info("Credentials revoked successfully")
			return nil
		}),
	}

	cmd.Flags().StringVarP(&leaseID, "lease-id", "l", "", "Vault lease ID to revoke")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")

	return cmd
}

func outputJSONCredential(credential *database_management.DatabaseCredential, showPassword bool) error {
	output := map[string]interface{}{
		"username":       credential.Username,
		"lease_id":       credential.LeaseID,
		"lease_duration": credential.LeaseDuration,
		"renewable":      credential.Renewable,
		"created_at":     credential.CreatedAt,
		"expires_at":     credential.ExpiresAt,
	}

	if showPassword {
		output["password"] = credential.Password
	} else {
		output["password"] = "[REDACTED]"
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func outputTableCredential(credential *database_management.DatabaseCredential, showPassword bool) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer func() {
		if err := w.Flush(); err != nil {
			// Best effort - log but don't fail
			fmt.Fprintf(os.Stderr, "Warning: failed to flush output: %v\n", err)
		}
	}()

	fmt.Printf("Dynamic Database Credentials\n")
	fmt.Printf("============================\n\n")

	if _, err := fmt.Fprintf(w, "Username:\t%s\n", credential.Username); err != nil {
		return fmt.Errorf("failed to write username: %w", err)
	}

	if showPassword {
		if _, err := fmt.Fprintf(w, "Password:\t%s\n", credential.Password); err != nil {
			return fmt.Errorf("failed to write password: %w", err)
		}
	} else {
		if _, err := fmt.Fprintf(w, "Password:\t[REDACTED - use --show-password to display]\n"); err != nil {
			return fmt.Errorf("failed to write password placeholder: %w", err)
		}
	}

	if _, err := fmt.Fprintf(w, "Lease ID:\t%s\n", credential.LeaseID); err != nil {
		return fmt.Errorf("failed to write lease ID: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Lease Duration:\t%d seconds\n", credential.LeaseDuration); err != nil {
		return fmt.Errorf("failed to write lease duration: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Renewable:\t%t\n", credential.Renewable); err != nil {
		return fmt.Errorf("failed to write renewable: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Created At:\t%s\n", credential.CreatedAt.Format("2006-01-02 15:04:05")); err != nil {
		return fmt.Errorf("failed to write created at: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Expires At:\t%s\n", credential.ExpiresAt.Format("2006-01-02 15:04:05")); err != nil {
		return fmt.Errorf("failed to write expires at: %w", err)
	}

	fmt.Printf("\nConnection String Example:\n")
	if showPassword {
		fmt.Printf("psql -h localhost -U %s -d delphi\n", credential.Username)
		fmt.Printf("Password: %s\n", credential.Password)
	} else {
		fmt.Printf("psql -h localhost -U %s -d delphi\n", credential.Username)
		fmt.Printf("Password: [Use --show-password to display]\n")
	}

	return nil
}
