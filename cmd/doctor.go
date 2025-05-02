// cmd/doctor.go

package cmd

import (
	"os"
	"os/user"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var DoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run EOS diagnostics to check system readiness",
	Long:  `This command checks for common system misconfigurations and provides remediation advice.`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("doctor")
		log.Info("🩺 Running EOS doctor...")

		currentUser, _ := user.Current()
		log.Info("👤 Current user", zap.String("username", currentUser.Username))

		ok, checkErr := system.CheckSudoersFile()
		if !ok {
			log.Warn("❌ /etc/sudoers.d/eos is missing or incorrect")
			log.Info("⚠️ Attempting to fix automatically...")
			if checkErr != nil {
				log.Warn("Failed to check sudoers file", zap.Error(checkErr))
			} else {
				log.Info("✅ Fixed sudoers file")
			}
		} else {
			log.Info("✅ /etc/sudoers.d/eos file is valid")
		}

		if _, err := os.Stat("/var/lib/eos"); os.IsNotExist(err) {
			log.Warn("❌ /var/lib/eos directory missing")
		} else {
			log.Info("✅ /var/lib/eos directory present")
		}

		log.Info("✅ EOS doctor check complete")
		return nil
	}),
}
