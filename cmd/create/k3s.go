// cmd/create/k3s.go
package create

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/network"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// k3sCmd is the subcommand for deploying K3s.
var CreateK3sCmd = &cobra.Command{
	Use:   "k3s",
	Short: "Deploy K3s on a server or worker node",
	Long: `Deploy K3s on a node with interactive prompts.
For server nodes, you'll be prompted for the TLS SAN.
For worker nodes, you'll be prompted for the server URL and node token.
Additional checks for IPv6 and Tailscale are performed.
The generated install command is previewed and saved to a script file
for safe, human-approved execution.`,
	Run: func(cmd *cobra.Command, args []string) {
		deployK3s()
	},
}

func init() {
	CreateCmd.AddCommand(CreateK3sCmd)
}

func deployK3s() {
	log := logger.GetLogger()
	reader := bufio.NewReader(os.Stdin)

	// Ask if this is a server or worker node.
	fmt.Print("Is this node a server or worker? [server/worker]: ")
	roleInput, err := reader.ReadString('\n')
	if err != nil {
		log.Error("Failed to read input", zap.Error(err))
		os.Exit(1)
	}
	role := strings.TrimSpace(strings.ToLower(roleInput))

	// Check for IPv6 support and try to detect a Tailscale IPv6 address.
	nodeIP := ""
	if network.CheckIPv6Enabled() {
		tailscaleIP, err := network.GetTailscaleIPv6()
		if err == nil && tailscaleIP != "" {
			nodeIP = tailscaleIP
			log.Info("Detected Tailscale IPv6", zap.String("node-ip", nodeIP))
		} else {
			log.Info("Tailscale IPv6 not detected; proceeding without --node-ip flag")
		}
	} else {
		log.Warn("IPv6 is disabled on this kernel. Attempting to enable it...")
		if err := network.EnableIPv6(); err != nil {
			log.Warn("Failed to enable IPv6 automatically; please enable it manually", zap.Error(err))
		} else {
			log.Info("IPv6 enabled successfully.")
		}
		// Try again after enabling
		tailscaleIP, err := network.GetTailscaleIPv6()
		if err == nil && tailscaleIP != "" {
			nodeIP = tailscaleIP
			log.Info("Detected Tailscale IPv6", zap.String("node-ip", nodeIP))
		}
	}

	// Check firewall ports (this stub can be extended as needed).
	checkFirewallPorts()

	var installCmd string

	if role == "server" {
		// Ask for TLS SAN with default
		fmt.Print("Enter TLS SAN (default: cluster.k3s.domain.com): ")
		tlsSANInput, _ := reader.ReadString('\n')
		tlsSAN := strings.TrimSpace(tlsSANInput)
		if tlsSAN == "" {
			tlsSAN = "cluster.k3s.domain.com"
		}

		installCmd = fmt.Sprintf("curl -sfL https://get.k3s.io | sh -s - server --tls-san %s", tlsSAN)
		if nodeIP != "" {
			installCmd += fmt.Sprintf(" --node-ip %s", nodeIP)
		}

	} else if role == "worker" {
		// Ask for the server URL and node token
		fmt.Print("Enter the K3s server URL (e.g., https://server-ip:6443): ")
		serverURLInput, _ := reader.ReadString('\n')
		serverURL := strings.TrimSpace(serverURLInput)

		// Wrap IPv6 in brackets
		if strings.Contains(serverURL, ":") && !strings.Contains(serverURL, "[") {
			serverURL = fmt.Sprintf("https://[%s]:6443", serverURL)
		} else if !strings.HasPrefix(serverURL, "https://") {
			serverURL = fmt.Sprintf("https://%s:6443", serverURL)
		}

		fmt.Print("Enter the K3s node token: ")
		tokenInput, _ := reader.ReadString('\n')
		token := strings.TrimSpace(tokenInput)

		// Worker: export env vars + pipe
		installCmd = fmt.Sprintf(
			"export K3S_URL=%s\nexport K3S_TOKEN=%s\ncurl -sfL https://get.k3s.io | sh -",
			serverURL, token,
		)
		if nodeIP != "" {
			installCmd += fmt.Sprintf(" --node-ip %s", nodeIP)
		}
	} else {
		fmt.Println("Invalid role. Please enter 'server' or 'worker'.")
		os.Exit(1)
	}

	// Display the generated install command for user confirmation.
	fmt.Println("\nGenerated install command:")
	fmt.Println(installCmd)
	fmt.Print("\nDo you want to execute this command? [y/N]: ")
	confirmInput, _ := reader.ReadString('\n')
	confirm := strings.TrimSpace(strings.ToLower(confirmInput))
	if confirm != "y" && confirm != "yes" {
		scriptPath := saveScript(installCmd)
		fmt.Printf("Installation command not executed. It has been saved to: %s\n", scriptPath)
		return
	}

	// Write the command to a script file.
	scriptPath := saveScript(installCmd)
	fmt.Printf("Executing the install script: %s\n", scriptPath)

	// Execute the script using sh.
	if err := execute.Execute("sh", scriptPath); err != nil {
		log.Error("Failed to execute install script", zap.Error(err))
		fmt.Println("Installation failed. Please check the logs for more details.")
		os.Exit(1)
	}

	fmt.Println("K3s deployment initiated. Follow any on-screen instructions as needed.")
	if role == "server" {
		// Output the join token after installation.
		outputJoinToken()
	}
}

// saveScript writes the install command to a script file and returns the file path.
func saveScript(cmdStr string) string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	dir := homeDir + "/.local/state/eos"
	os.MkdirAll(dir, 0755)
	scriptPath := dir + "/k3s-install.sh"
	scriptContent := "#!/bin/sh\n" + cmdStr + "\n"
	err = os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	if err != nil {
		fmt.Printf("Warning: Failed to write script file: %v\n", err)
	}
	return scriptPath
}

// checkFirewallPorts performs a basic check for firewall status by attempting
// to list firewall rules using common tools (ufw or iptables).
func checkFirewallPorts() {
	fmt.Println("Checking firewall ports...")

	// Try to detect UFW (Uncomplicated Firewall)
	if ufwPath, err := exec.LookPath("ufw"); err == nil {
		fmt.Printf("UFW detected at %s. Fetching status...\n", ufwPath)
		out, err := exec.Command("sudo", "ufw", "status", "verbose").CombinedOutput()
		if err != nil {
			fmt.Printf("Warning: Failed to get UFW status: %v\n", err)
		} else {
			fmt.Println("UFW status:")
			fmt.Println(string(out))
		}
		return
	}

	// If UFW isn't found, try iptables
	if iptablesPath, err := exec.LookPath("iptables"); err == nil {
		fmt.Printf("iptables detected at %s. Listing rules...\n", iptablesPath)
		out, err := exec.Command("sudo", "iptables", "-L", "-n").CombinedOutput()
		if err != nil {
			fmt.Printf("Warning: Failed to get iptables status: %v\n", err)
		} else {
			fmt.Println("iptables status:")
			fmt.Println(string(out))
		}
		return
	}

	// If neither firewall tool is detected, warn the user.
	fmt.Println("No recognized firewall management tool (ufw or iptables) was found.")
	fmt.Println("Please ensure that the following ports are not blocked by your firewall:")
	fmt.Println("- TCP 6443 (Kubernetes API server)")
	fmt.Println("- TCP 10250 (kubelet)")
	fmt.Println("- Other required ports as per your network configuration")
}

// outputJoinToken waits for the K3s join token to be available and prints it.
func outputJoinToken() {
	tokenPath := "/var/lib/rancher/k3s/server/node-token"
	fmt.Println("Retrieving K3s join token...")
	maxAttempts := 30
	for i := 0; i < maxAttempts; i++ {
		tokenData, err := os.ReadFile(tokenPath)
		if err == nil {
			token := strings.TrimSpace(string(tokenData))
			if token != "" {
				fmt.Printf("K3s Join Token: %s\n", token)
				return
			}
		}
		time.Sleep(1 * time.Second)
	}
	fmt.Println("Unable to retrieve join token. Please check the K3s server status.")
}
