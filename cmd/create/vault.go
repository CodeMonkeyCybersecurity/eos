// cmd/create/vault.go
package create

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Installs and initializes HashiCorp Vault in production mode",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := zap.L()

		vault.SetVaultEnv()

		log.Info("Killing any existing Vault server process")
		_ = exec.Command("pkill", "-f", "vault server").Run()
		time.Sleep(3 * time.Second)

		if platform.GetOSPlatform() != "linux" {
			log.Fatal("Vault deployment only supported on Linux")
		}

		distro := platform.DetectLinuxDistro()

		switch distro {
		case "debian":
			log.Info("Adding HashiCorp APT repository")
			keyringPath := "/usr/share/keyrings/hashicorp-archive-keyring.gpg"
			listPath := "/etc/apt/sources.list.d/hashicorp.list"

			// Clean up if keyring already exists to avoid interactive overwrite prompt
			if _, err := os.Stat(keyringPath); err == nil {
				log.Warn("Vault APT keyring already exists, removing to prevent prompt", zap.String("path", keyringPath))
				if err := os.Remove(keyringPath); err != nil {
					log.Fatal("Failed to remove existing APT keyring", zap.Error(err))
				}
			}

			// Clean up the repo list file as well if needed
			if _, err := os.Stat(listPath); err == nil {
				log.Warn("Vault APT source list already exists, removing to avoid duplicate", zap.String("path", listPath))
				if err := os.Remove(listPath); err != nil {
					log.Fatal("Failed to remove existing source list", zap.Error(err))
				}
			}

			aptCmd := exec.Command("bash", "-c", `curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg && echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list`)
			aptCmd.Stdout = os.Stdout
			aptCmd.Stderr = os.Stderr
			if err := aptCmd.Run(); err != nil {
				log.Fatal("Failed to add APT repo", zap.Error(err))
			}

			log.Info("Installing Vault via apt")
			_ = exec.Command("apt-get", "update").Run()
			installCmd := exec.Command("apt-get", "install", "-y", "vault")
			installCmd.Stdout = os.Stdout
			installCmd.Stderr = os.Stderr
			if err := installCmd.Run(); err != nil {
				log.Fatal("Failed to install Vault via apt", zap.Error(err))
			}

		case "rhel":
			log.Info("Installing Vault via dnf")
			repoFile := "/etc/yum.repos.d/hashicorp.repo"
			if _, err := os.Stat(repoFile); os.IsNotExist(err) {
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
			dnfCmd := exec.Command("dnf", "install", "-y", "vault")
			dnfCmd.Stdout = os.Stdout
			dnfCmd.Stderr = os.Stderr
			if err := dnfCmd.Run(); err != nil {
				log.Fatal("Failed to install Vault via dnf", zap.Error(err))
			}
		}

		if _, err := exec.LookPath("vault"); err != nil {
			log.Fatal("Vault CLI not found after install", zap.Error(err))
		}

		configDir := "/etc/vault.d"
		if distro != "debian" && distro != "rhel" {
			configDir = "/var/snap/vault/common"
		}

		configFile := configDir + "/config.hcl"
		_ = os.MkdirAll(configDir, 0755)
		_ = os.MkdirAll("/opt/vault/data", 0755)

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

		log.Info("Writing Vault config", zap.String("path", configFile))
		if err := os.WriteFile(configFile, []byte(config), 0644); err != nil {
			log.Fatal("Failed to write Vault config", zap.Error(err))
		}

		log.Info("Starting Vault process", zap.String("config", configFile))
		startCmd := exec.Command("vault", "server", "-config="+configFile)
		if err := startCmd.Start(); err != nil {
			log.Fatal("Failed to start Vault", zap.String("action", "start"), zap.Error(err))
		}

		log.Info("Vault started", zap.Int("pid", startCmd.Process.Pid))
		return nil
	},
	)}

func init() {
	CreateCmd.AddCommand(CreateVaultCmd)
}
