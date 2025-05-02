// cmd/doctor.go

package cmd

import (
	"fmt"
	"os"
	"os/user"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/spf13/cobra"
)

var DoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run EOS diagnostics to check system readiness",
	Long:  `This command checks for common system misconfigurations and provides remediation advice.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🩺 Running EOS doctor...")

		currentUser, _ := user.Current()
		fmt.Printf("👤 Current user: %s\n", currentUser.Username)
		info, err := os.Stat(shared.EosSudoersPath)
		if os.IsNotExist(err) {
			fmt.Println("❌ /etc/sudoers.d/eos file missing")
		} else {
			fmt.Println("✅ /etc/sudoers.d/eos file present")
			if info.Mode().Perm() != 0440 {
				fmt.Printf("❌ /etc/sudoers.d/eos has wrong permissions: %o\n", info.Mode().Perm())
				fmt.Println("➡️  Should be 440; will attempt to fix with `eos bootstrap` or `FixSudoersFile()`")
			} else {
				fmt.Println("✅ /etc/sudoers.d/eos permissions are correct (440)")
			}
		}
		if _, err := os.Stat("/etc/sudoers.d/eos"); os.IsNotExist(err) {
			fmt.Println("❌ /etc/sudoers.d/eos file missing")
		} else {
			fmt.Println("✅ /etc/sudoers.d/eos file present")
		}
		if !system.CheckSudoersMembership("eos") {
			fmt.Println("❌ eos user is missing from sudoers.")
			fmt.Println("➡️  Add this line to /etc/sudoers.d/eos:")
			fmt.Println("    eos ALL=(ALL) NOPASSWD: /bin/systemctl")
		} else {
			fmt.Println("✅ eos user is present in sudoers")
		}

		if !system.CanSudoSystemctl("status", "vault") {
			fmt.Println("❌ eos user lacks NOPASSWD sudo for systemctl.")
		} else {
			fmt.Println("✅ NOPASSWD sudo check passed")
		}

		if _, err := os.Stat("/var/lib/eos"); os.IsNotExist(err) {
			fmt.Println("❌ /var/lib/eos directory missing")
		} else {
			fmt.Println("✅ /var/lib/eos directory present")
		}

		fmt.Println("✅ EOS doctor check complete")
	},
}
