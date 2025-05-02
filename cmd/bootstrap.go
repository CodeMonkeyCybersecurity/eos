// cmd /bootstrap.go

package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/spf13/cobra"
)

var BootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Prepare the system for EOS installation with eos user, sudoers, and directories",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🚀 Running EOS bootstrap...")

		// 1. Check/create eos user
		_, err := exec.Command("id", "-u", "eos").Output()
		if err != nil {
			fmt.Println("👤 Creating eos user...")
			exec.Command("sudo", "useradd", "-r", "-s", "/usr/sbin/nologin", "eos").Run()
		} else {
			fmt.Println("✅ eos user exists")
		}

		// 2. Add eos to sudoers
		sudoersLine := "eos ALL=(ALL) NOPASSWD: /bin/systemctl"
		exec.Command("sudo", "bash", "-c", fmt.Sprintf("echo '%s' > /etc/sudoers.d/eos", sudoersLine)).Run()
		exec.Command("sudo", "chmod", "440", "/etc/sudoers.d/eos").Run()
		fmt.Println("✅ Added eos to sudoers")

		if !system.CheckSudoersMembership("eos") {
			fmt.Println("❌ eos missing from sudoers")
		}

		// 3. Create directories
		os.MkdirAll(shared.VarEos, 0750)
		os.MkdirAll(shared.VarEos, 0750)
		fmt.Println("✅ Created /var/lib/eos and /var/log/eos")

		fmt.Println("🎉 EOS bootstrap complete. You are ready to install EOS.")
	},
}
