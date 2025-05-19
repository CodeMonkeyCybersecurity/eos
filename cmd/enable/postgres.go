// cmd/enable/postgres.go

package enable

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/postgres"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var EnablePostgresCmd = &cobra.Command{
	Use:   "postgres",
	Short: "Initialize PostgreSQL schema for EOS",
	RunE: eoscli.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := zap.L().Named("enable.postgres")

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
