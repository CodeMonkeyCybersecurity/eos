package install

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"eos/pkg/utils"
	"github.com/spf13/cobra"
)

// vaultCmd represents the vault command under the "install" group.
var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Installs and initializes HashiCorp Vault in production mode via snap",
	Long: `This command installs HashiCorp Vault using snap and starts Vault in production mode.
A minimal configuration file is generated and used to run Vault with persistent file storage.
After starting, Vault is automatically initialized and unsealed if not already done.
Live log monitoring is performed to detect the startup marker, then the script polls for Vault status.
This is a quick prod-mode setup, not intended for production use without further hardening.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Kill any existing Vault process.
		fmt.Println("Killing any existing Vault server process...")
		killCmd := exec.Command("pkill", "-f", "vault server")
		killCmd.Run() // Ignore error if process is not running.
		time.Sleep(3 * time.Second)

		// Install Vault via snap.
		fmt.Println("Installing HashiCorp Vault via snap...")
		installCmd := exec.Command("snap", "install", "vault", "--classic")
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr
		if err := installCmd.Run(); err != nil {
			log.Fatalf("Failed to install Vault: %v", err)
		}

		// Verify installation.
		if _, err := exec.LookPath("vault"); err != nil {
			log.Fatal("Vault command not found after installation.")
		}

		// Set VAULT_ADDR.
		hostname := utils.GetInternalHostname()
		vaultAddr := fmt.Sprintf("http://%s:8179", hostname)
		os.Setenv("VAULT_ADDR", vaultAddr)
		fmt.Printf("VAULT_ADDR is set to %s\n", vaultAddr)

		// Create Vault configuration file.
		configDir := "/var/snap/vault/common"
		configFile := configDir + "/config.hcl"
		if err := os.MkdirAll(configDir, 0755); err != nil {
			log.Fatalf("Failed to create config directory %s: %v", configDir, err)
		}
		configContent := fmt.Sprintf(`
listener "tcp" {
  address     = "0.0.0.0:8179"
  tls_disable = 1
}

storage "file" {
  path = "/var/snap/vault/common/data"
}

disable_mlock = true
api_addr = "%s"
ui = true
`, vaultAddr)
		if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
			log.Fatalf("Failed to write config file: %v", err)
		}
		fmt.Printf("Vault configuration written to %s\n", configFile)

		// Start Vault in production mode.
		fmt.Println("Starting Vault in production mode...")
		logFilePath := "/var/log/vault.log"
		logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		vaultServerCmd := exec.Command("vault", "server", "-config="+configFile)
		vaultServerCmd.Stdout = logFile
		vaultServerCmd.Stderr = logFile
		if err := vaultServerCmd.Start(); err != nil {
			log.Fatalf("Failed to start Vault server: %v", err)
		}
		fmt.Printf("Vault process started with PID %d\n", vaultServerCmd.Process.Pid)

		// Live log monitoring.
		fmt.Println("Monitoring Vault logs for startup message...")
		marker := "Vault server started!"
		timeout := 60 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		tailCmd := exec.CommandContext(ctx, "tail", "-n", "100", "-f", logFilePath)
		stdout, err := tailCmd.StdoutPipe()
		if err != nil {
			log.Fatalf("Failed to get stdout pipe: %v", err)
		}
		if err := tailCmd.Start(); err != nil {
			log.Fatalf("Failed to start tail command: %v", err)
		}

		scanner := bufio.NewScanner(stdout)
		foundMarker := false
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println(line)
			if strings.Contains(line, marker) {
				foundMarker = true
				cancel() // Cancel context to stop tailing.
				break
			}
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading log output: %v", err)
		}
		// Wait for tail command to finish, but don't exit on cancellation.
		if err := tailCmd.Wait(); err != nil {
			if ctx.Err() == context.Canceled {
				log.Println("Tail command canceled after detecting startup marker.")
			} else if ctx.Err() == context.DeadlineExceeded {
				log.Println("Timeout reached while waiting for startup marker.")
			} else {
				log.Printf("Tail command exited with error: %v", err)
			}
		}
		if !foundMarker {
			log.Println("Startup marker not found; proceeding with existing logs.")
		}

		// Poll for Vault status up to 30 seconds.
		var vaultStatus struct {
			Initialized bool `json:"initialized"`
			Sealed      bool `json:"sealed"`
		}
		maxAttempts := 30
		attempt := 0
		for {
			statusCmd := exec.Command("vault", "status", "-format=json")
			statusOut, err := statusCmd.Output()
			if err == nil {
				if err := json.Unmarshal(statusOut, &vaultStatus); err == nil {
					break
				}
			}
			attempt++
			if attempt >= maxAttempts {
				log.Fatalf("Failed to get valid Vault status after %d attempts.", attempt)
			}
			time.Sleep(1 * time.Second)
		}

		// Initialize and unseal Vault if necessary.
		if !vaultStatus.Initialized {
			fmt.Println("Vault is not initialized. Initializing Vault...")
			initCmd := exec.Command("vault", "operator", "init", "-key-shares=5", "-key-threshold=3", "-format=json")
			initOut, err := initCmd.Output()
			if err != nil {
				log.Fatalf("Failed to initialize Vault: %v", err)
			}
			var initResult struct {
				UnsealKeysB64 []string `json:"unseal_keys_b64"`
				RootToken     string   `json:"root_token"`
			}
			if err := json.Unmarshal(initOut, &initResult); err != nil {
				log.Fatalf("Failed to parse initialization output: %v", err)
			}
			fmt.Println("Vault initialized successfully!")
			for i := 0; i < 3; i++ {
				fmt.Printf("Unsealing Vault with key %d...\n", i+1)
				unsealCmd := exec.Command("vault", "operator", "unseal", initResult.UnsealKeysB64[i])
				unsealCmd.Stdout = os.Stdout
				unsealCmd.Stderr = os.Stderr
				if err := unsealCmd.Run(); err != nil {
					log.Fatalf("Failed to unseal Vault: %v", err)
				}
			}
			fmt.Println("Vault unsealed successfully!")
			fmt.Printf("Root Token (save this securely!): %s\n", initResult.RootToken)
		} else if vaultStatus.Sealed {
			fmt.Println("Vault is initialized but sealed. Manual intervention required to unseal.")
			return
		} else {
			fmt.Println("Vault is already initialized and unsealed.")
		}

		fmt.Println("Vault is now running in production mode...")
		fmt.Printf("Access it at %s.\n", vaultAddr)
		fmt.Println("To view Vault logs, check", logFilePath)
	},
}

func init() {
	InstallCmd.AddCommand(vaultCmd)
}
