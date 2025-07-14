package read

import (
	"encoding/json"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/database_management"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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
			return outputJSONCredential(logger, credential, showPassword)
		}

		return outputTableCredential(logger, credential, showPassword)
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

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func outputJSONCredential(logger otelzap.LoggerWithCtx, credential *database_management.DatabaseCredential, showPassword bool) error {
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
	logger.Info("terminal prompt: JSON output", zap.String("data", string(data)))
	return nil
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func outputTableCredential(logger otelzap.LoggerWithCtx, credential *database_management.DatabaseCredential, showPassword bool) error {
	logger.Info("terminal prompt: Dynamic Database Credentials")
	logger.Info("terminal prompt: ============================")

	logger.Info("terminal prompt: Username", zap.String("value", credential.Username))

	if showPassword {
		logger.Info("terminal prompt: Password", zap.String("value", credential.Password))
	} else {
		logger.Info("terminal prompt: Password", zap.String("value", "[REDACTED - use --show-password to display]"))
	}

	logger.Info("terminal prompt: Lease ID", zap.String("value", credential.LeaseID))
	logger.Info("terminal prompt: Lease Duration", zap.Int("seconds", credential.LeaseDuration))
	logger.Info("terminal prompt: Renewable", zap.Bool("value", credential.Renewable))
	logger.Info("terminal prompt: Created At", zap.String("value", credential.CreatedAt.Format("2006-01-02 15:04:05")))
	logger.Info("terminal prompt: Expires At", zap.String("value", credential.ExpiresAt.Format("2006-01-02 15:04:05")))

	logger.Info("terminal prompt: Connection String Example:")
	if showPassword {
		logger.Info("terminal prompt: psql -h localhost -U X -d delphi", zap.String("username", credential.Username))
		logger.Info("terminal prompt: Password", zap.String("password", credential.Password))
	} else {
		logger.Info("terminal prompt: psql -h localhost -U X -d delphi", zap.String("username", credential.Username))
		logger.Info("terminal prompt: Password: [Use --show-password to display]")
	}

	return nil
}
