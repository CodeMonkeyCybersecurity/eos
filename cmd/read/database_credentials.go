package read

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/database_management"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var databaseCredentialsCmd = &cobra.Command{
	Use:     "database-credentials",
	Aliases: []string{"database-creds", "db-credentials", "db-creds"},
	Short:   "Generate and view dynamic database credentials",
	Long: `Generate and view dynamic database credentials through Vault.

This command provides credential viewing functionality:
- Generate new dynamic credentials  
- View active credential details
- Check credential status and expiration

Examples:
  eos read database-credentials --role delphi-readonly
  eos read database-credentials --role delphi-readonly --json
  eos read database-credentials --role myapp-user --show-password`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		roleName, _ := cmd.Flags().GetString("role")
		engineMount, _ := cmd.Flags().GetString("engine-mount")
		outputJSON, _ := cmd.Flags().GetBool("json")
		showPassword, _ := cmd.Flags().GetBool("show-password")

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

func init() {
	databaseCredentialsCmd.Flags().StringP("role", "r", "", "Database role name")
	databaseCredentialsCmd.Flags().String("engine-mount", "database", "Vault database engine mount point")
	databaseCredentialsCmd.Flags().Bool("json", false, "Output in JSON format")
	databaseCredentialsCmd.Flags().Bool("show-password", false, "Show password in output")

	// Register with parent command
	ReadCmd.AddCommand(databaseCredentialsCmd)
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