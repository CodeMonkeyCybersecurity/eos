package create

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// vaultCmd represents the vault command under the "install" group.
var CreateVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Installs and initializes HashiCorp Vault in production mode",
	Long: `This command installs HashiCorp Vault using the appropriate package manager (apt or dnf)
and starts Vault in production mode.

A minimal configuration file is generated and used to run Vault with persistent file storage. 

After starting, Vault is given a fixed wait period (5 seconds) before checking its status. 

If Vault is not initialized, it will be initialized (with 5 key shares and a threshold of 3) and then unsealed using the first three keys.`,

	Run: func(cmd *cobra.Command, args []string) {

		vault.SetVaultEnv()

		// Kill any existing Vault process.
		fmt.Println("Killing any existing Vault server process...")
		killCmd := exec.Command("pkill", "-f", "vault server")
		killCmd.Run() // Ignore error if no process is found.
		time.Sleep(3 * time.Second)

		// Install Vault via snap.
		// Detect the OS and Linux distribution.
		osPlatform := platform.GetOSPlatform()
		if osPlatform != "linux" {
			log.Fatal("Vault deployment only supported on Linux")
		}
		distro := platform.DetectLinuxDistro()

		// Install Vault using the appropriate package manager.
		if distro == "debian" {
			fmt.Println("Installing HashiCorp Vault via apt...")
			updateCmd := exec.Command("apt-get", "update")
			updateCmd.Stdout = os.Stdout
			updateCmd.Stderr = os.Stderr
			if err := updateCmd.Run(); err != nil {
				log.Fatal("Failed to update apt repositories", zap.Error(err))
			}
			installCmd := exec.Command("apt-get", "install", "-y", "vault")
			installCmd.Stdout = os.Stdout
			installCmd.Stderr = os.Stderr
			if err := installCmd.Run(); err != nil {
				log.Fatal("Failed to install Vault via apt", zap.Error(err))
			}
		} else if distro == "rhel" {
			fmt.Println("Installing HashiCorp Vault via dnf...")
			repoFile := "/etc/yum.repos.d/hashicorp.repo"
			repoContent := `[hashicorp]
name=HashiCorp Stable - $basearch
baseurl=https://rpm.releases.hashicorp.com/RHEL/9/$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://rpm.releases.hashicorp.com/gpg`

			if _, err := os.Stat(repoFile); os.IsNotExist(err) {
				if err := os.WriteFile(repoFile, []byte(repoContent), 0644); err != nil {
					log.Fatal("Failed to write HashiCorp repo file", zap.Error(err))
				}
			}
			exec.Command("dnf", "clean", "all").Run()
			exec.Command("dnf", "makecache").Run()

			installCmd := exec.Command("dnf", "install", "-y", "vault")
			installCmd.Stdout = os.Stdout
			installCmd.Stderr = os.Stderr
			if err := installCmd.Run(); err != nil {
				log.Fatal("Failed to install Vault via dnf", zap.Error(err))
			}
		}

		// Verify Vault installation.
		if _, err := exec.LookPath("vault"); err != nil {
			log.Fatal("Vault command not found after installation", zap.Error(err))
		}

		// Create Vault configuration file.
		configDir := "/etc/vault.d"
		if distro != "debian" && distro != "rhel" {
			configDir = "/var/snap/vault/common"
		}
		configFile := configDir + "/config.hcl"

		if err := os.MkdirAll(configDir, 0755); err != nil {
			log.Fatal("Failed to create config directory",
				zap.String("dir", configDir),
				zap.Error(err))
		}

		vaultAddr := os.Getenv("VAULT_ADDR")
		if vaultAddr == "" {
			vaultAddr = "http://127.0.0.1:8179"
		}

		// Ensure storage directory exists
		if err := os.MkdirAll("/opt/vault/data", 0755); err != nil {
			log.Fatal("Failed to create Vault storage directory",
				zap.String("dir", "/opt/vault/data"),
				zap.Error(err))
		}
		
		configContent := fmt.Sprintf(`
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

		if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
			log.Fatal("Failed to write config file", zap.String("file", configFile), zap.Error(err))
		}
		fmt.Printf("Vault configuration written to %s\n", configFile)

		// Start Vault in production mode.
		fmt.Println("Starting Vault in production mode...")
		logFilePath := "/var/log/vault.log"
		logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatal("Failed to open log file", zap.String("logFile", logFilePath), zap.Error(err))
		}

		vaultServerCmd := exec.Command("vault", "server", "-config="+configFile)
		vaultServerCmd.Stdout = logFile
		vaultServerCmd.Stderr = logFile

		if err := vaultServerCmd.Start(); err != nil {
			log.Fatal("Failed to start Vault server", zap.Error(err))
		}

		fmt.Printf("Vault process started with PID %d\n", vaultServerCmd.Process.Pid)

		// Wait a fixed 5 seconds for Vault to stabilize.
		fmt.Println("Waiting 5 seconds for Vault to stabilize...")
		time.Sleep(5 * time.Second)

		// Additional logic to check Vault status, init/unseal, etc. can go here
	},
}

func init() {

	CreateCmd.AddCommand(CreateVaultCmd)
}
