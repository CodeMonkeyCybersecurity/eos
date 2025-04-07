// cmd/create/vault.go

package create

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/flags"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Installs and initializes HashiCorp Vault in production mode",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		vault.SetVaultEnv()

		if flags.IsDryRun() {
			fmt.Println("🧪 Dry run: Skipping Vault installation and startup.")
		}

		// Kill any existing Vault server
		fmt.Println("Killing any existing Vault server process...")
		if !flags.IsDryRun() {
			_ = exec.Command("pkill", "-f", "vault server").Run()
			time.Sleep(3 * time.Second)
		}

		if platform.GetOSPlatform() != "linux" {
			log.Fatal("Vault deployment only supported on Linux")
		}
		distro := platform.DetectLinuxDistro()

		if distro == "debian" {
			fmt.Println("Adding HashiCorp APT repository...")
			if !flags.IsDryRun() {
				cmd := exec.Command("bash", "-c", `
curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg && \
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/hashicorp.list
`)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					log.Fatal("Failed to add APT repo", zap.Error(err))
				}
			}

			fmt.Println("Installing Vault via apt...")
			if !flags.IsDryRun() {
				_ = exec.Command("apt-get", "update").Run()
				cmd := exec.Command("apt-get", "install", "-y", "vault")
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					log.Fatal("Failed to install vault via apt", zap.Error(err))
				}
			}

			if !flags.IsDryRun() {
				if _, err := exec.LookPath("vault"); err != nil {
					log.Fatal("Vault CLI not found after install", zap.Error(err))
				}
			}

		} else if distro == "rhel" {
			fmt.Println("Installing Vault via dnf...")
			repoFile := "/etc/yum.repos.d/hashicorp.repo"

			if !flags.IsDryRun() {
				_, err := os.Stat(repoFile)
				if os.IsNotExist(err) {
					repoContent := `[hashicorp]
name=HashiCorp Stable - $basearch
baseurl=https://rpm.releases.hashicorp.com/RHEL/9/$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://rpm.releases.hashicorp.com/gpg`

					if err := os.WriteFile(repoFile, []byte(repoContent), 0644); err != nil {
						log.Fatal("Failed to write HashiCorp repo file", zap.Error(err))
					}
				}

				_ = exec.Command("dnf", "clean", "all").Run()
				_ = exec.Command("dnf", "makecache").Run()

				cmd := exec.Command("dnf", "install", "-y", "vault")
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					log.Fatal("Failed to install vault via dnf", zap.Error(err))
				}
			}
		}
		// Config file setup
		configDir := "/etc/vault.d"
		if distro != "debian" && distro != "rhel" {
			configDir = "/var/snap/vault/common"
		}
		configFile := configDir + "/config.hcl"

		if !flags.IsDryRun() {
			_ = os.MkdirAll(configDir, 0755)
			_ = os.MkdirAll("/opt/vault/data", 0755)
		}

		vaultAddr := os.Getenv("VAULT_ADDR")
		if vaultAddr == "" {
			vaultAddr = "http://127.0.0.1:8179"
		}
		config := fmt.Sprintf(`
listener "tcp" {
  address     = "0.0.0.0:8179"
  tls_disable = 1
}
storage "file" {
  path = "/opt/vault/data"
}
disable_mlock = true
api_addr = "%s"
ui = true
`, vaultAddr)

		fmt.Printf("Writing Vault config to %s\n", configFile)
		if !flags.IsDryRun() {
			if err := os.WriteFile(configFile, []byte(config), 0644); err != nil {
				log.Fatal("Failed to write config", zap.Error(err))
			}
		}

		fmt.Println("Starting Vault in production mode...")
		if !flags.IsDryRun() {
			logFile, err := os.OpenFile("/var/log/vault.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				log.Fatal("Cannot open log file", zap.Error(err))
			}
			cmd := exec.Command("vault", "server", "-config="+configFile)
			cmd.Stdout = logFile
			cmd.Stderr = logFile
			if err := cmd.Start(); err != nil {
				log.Fatal("Failed to start Vault", zap.Error(err))
			}
			fmt.Printf("Vault process started with PID %d\n", cmd.Process.Pid)
		}

		fmt.Println("Waiting 5 seconds for Vault to stabilize...")
		if !flags.IsDryRun() {
			time.Sleep(5 * time.Second)
		}

		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateVaultCmd)
	flags.AddDryRunFlags(CreateVaultCmd)
}
