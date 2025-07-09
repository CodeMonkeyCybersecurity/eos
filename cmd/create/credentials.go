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

// credentialsCmd manages dynamic database credentials
var credentialsCmd = &cobra.Command{
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
  eos create credentials generate --role delphi-readonly
  eos create credentials revoke --lease-id vault:db:123
  eos create credentials list --role delphi-readonly`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for credentials command")
		_ = cmd.Help()
		return nil
	}),
}

// generateCredentialsCmd generates new dynamic database credentials
var generateCredentialsCmd = &cobra.Command{
	Use:     "generate",
	Aliases: []string{"gen"},
	Short:   "Generate new dynamic database credentials",
	Long: `Generate new dynamic database credentials for a specific role.

Examples:
  eos create credentials generate --role delphi-readonly
  eos create credentials generate --role delphi-readonly --json
  eos create credentials generate --role myapp-user --show-password`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		roleName, _ := cmd.Flags().GetString("role")
		if roleName == "" {
			return fmt.Errorf("role name is required (use --role)")
		}

		logger.Info("Generating dynamic database credentials", zap.String("role", roleName))

		manager := database_management.NewDatabaseManager()

		engineMount, _ := cmd.Flags().GetString("engine-mount")
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

		outputJSON, _ := cmd.Flags().GetBool("json")
		showPassword, _ := cmd.Flags().GetBool("show-password")

		if outputJSON {
			return outputJSONCredential(credential, showPassword)
		}

		return outputTableCredential(credential, showPassword)
	}),
}

// revokeCredentialsCmd revokes dynamic database credentials
var revokeCredentialsCmd = &cobra.Command{
	Use:     "revoke",
	Aliases: []string{"rev"},
	Short:   "Revoke dynamic database credentials",
	Long: `Revoke dynamic database credentials by lease ID.

Examples:
  eos create credentials revoke --lease-id vault:db:123456
  eos create credentials revoke --lease-id vault:db:123456 --force`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		leaseID, _ := cmd.Flags().GetString("lease-id")
		if leaseID == "" {
			return fmt.Errorf("lease ID is required (use --lease-id)")
		}

		logger.Info("Revoking database credentials", zap.String("lease_id", leaseID))

		force, _ := cmd.Flags().GetBool("force")
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

func init() {
	// Register credentialsCmd with CreateCmd
	CreateCmd.AddCommand(credentialsCmd)
	
	// Add subcommands to credentialsCmd
	credentialsCmd.AddCommand(generateCredentialsCmd)
	credentialsCmd.AddCommand(revokeCredentialsCmd)
	
	// Set up flags for generateCredentialsCmd
	generateCredentialsCmd.Flags().StringP("role", "r", "", "Database role name")
	generateCredentialsCmd.Flags().String("engine-mount", "database", "Vault database engine mount point")
	generateCredentialsCmd.Flags().Bool("json", false, "Output in JSON format")
	generateCredentialsCmd.Flags().Bool("show-password", false, "Show password in output")
	
	// Set up flags for revokeCredentialsCmd
	revokeCredentialsCmd.Flags().StringP("lease-id", "l", "", "Vault lease ID to revoke")
	revokeCredentialsCmd.Flags().BoolP("force", "f", false, "Skip confirmation prompt")
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
