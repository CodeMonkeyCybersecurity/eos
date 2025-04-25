// cmd/create/k3s.go
package create

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"

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
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		deployK3s()
		return nil
	}),
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

	// Check for IPv6 support and Tailscale IPv6.
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
		log.Warn("IPv6 is disabled. Attempting to enable it...")
		if err := network.EnableIPv6(); err != nil {
			log.Warn("Could not enable IPv6", zap.Error(err))
		} else {
			log.Info("IPv6 enabled. Retrying Tailscale detection...")
			if ip, err := network.GetTailscaleIPv6(); err == nil && ip != "" {
				nodeIP = ip
				log.Info("Detected Tailscale IPv6", zap.String("node-ip", nodeIP))
			}
		}
	}

	// 🔥 Unified firewall status check
	platform.CheckFirewallStatus(log)

	var installCmd string

	switch role {
	case "server":
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

	case "worker":
		fmt.Print("Enter the K3s server URL (e.g., https://server-ip:6443): ")
		serverURLInput, _ := reader.ReadString('\n')
		serverURL := strings.TrimSpace(serverURLInput)

		if strings.Contains(serverURL, ":") && !strings.Contains(serverURL, "[") {
			serverURL = fmt.Sprintf("https://[%s]:6443", serverURL)
		} else if !strings.HasPrefix(serverURL, "https://") {
			serverURL = fmt.Sprintf("https://%s:6443", serverURL)
		}

		fmt.Print("Enter the K3s node token: ")
		tokenInput, _ := reader.ReadString('\n')
		token := strings.TrimSpace(tokenInput)

		installCmd = fmt.Sprintf(
			"export K3S_URL=%s\nexport K3S_TOKEN=%s\ncurl -sfL https://get.k3s.io | sh -s -",
			serverURL, token,
		)
		if nodeIP != "" {
			installCmd += fmt.Sprintf(" --node-ip %s", nodeIP)
		}

	default:
		fmt.Println("Invalid role. Please enter 'server' or 'worker'.")
		os.Exit(1)
	}

	fmt.Println("\nGenerated install command:")
	fmt.Println(installCmd)
	fmt.Print("\nDo you want to execute this command? [y/N]: ")
	confirmInput, _ := reader.ReadString('\n')
	confirm := strings.TrimSpace(strings.ToLower(confirmInput))
	if confirm != "y" && confirm != "yes" {
		scriptPath := saveScript(installCmd)
		fmt.Printf("Installation command not executed. Saved to: %s\n", scriptPath)
		return
	}

	scriptPath := saveScript(installCmd)
	fmt.Printf("Executing the install script: %s\n", scriptPath)
	fmt.Println("Check /var/log/eos/k3s-deploy.log for details.")
	fmt.Println("To monitor logs in real time: tail -f /var/log/eos/k3s-deploy.log")

	if err := execute.Execute("sh", scriptPath); err != nil {
		log.Error("Failed to execute install script", zap.Error(err))
		fmt.Println("Installation failed. Check logs for details.")
		os.Exit(1)
	}

	fmt.Println("K3s deployment initiated.")
	if role == "server" {
		outputJoinToken()
	}
}

// saveScript writes the install command to a script file and returns the file path.
func saveScript(cmdStr string) string {
	// Ensure the log directory exists
	logDir := "/var/log/eos"
	if err := os.MkdirAll(logDir, shared.DirPermStandard); err != nil {
		fmt.Printf("Warning: Could not create log directory %s: %v\n", logDir, err)
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	dir := homeDir + "/.local/state/eos"
	if err := os.MkdirAll(dir, shared.DirPermStandard); err != nil {
		log.Warn("Failed to create directory for install script", zap.String("path", dir), zap.Error(err))
	}
	scriptPath := dir + "/k3s-install.sh"
	// Prepend with set -x for debugging and redirect output to a log file.
	scriptContent := fmt.Sprintf(`#!/bin/sh
set -x
exec > >(tee -a %s/k3s-deploy.log) 2>&1
%s
`, logDir, cmdStr)
	err = os.WriteFile(scriptPath, []byte(scriptContent), shared.DirPermStandard)
	if err != nil {
		fmt.Printf("Warning: Failed to write script file: %v\n", err)
	}
	return scriptPath
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
