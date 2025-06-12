// cmd/enable/postgres.go

package enable

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	postgres "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_postgres"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var EnablePostgresCmd = &cobra.Command{
	Use:   "postgres",
	Short: "Initialize PostgreSQL schema for Eos",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		db, err := postgres.Connect()
		if err != nil {
			log.Error("failed to connect to DB", zap.Error(err))
			return err
		}

		if err := postgres.Migrate(db); err != nil {
			log.Error("failed to migrate schema", zap.Error(err))
			return err
		}

		log.Info("PostgreSQL schema initialized")
		return nil
	}),
}

func init() {
	EnableCmd.AddCommand(EnablePostgresCmd)
}
