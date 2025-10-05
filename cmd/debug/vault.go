// cmd/debug/vault.go
// Comprehensive Vault debugging command

package debug

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var debugVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Debug Vault installation and configuration",
	Long: `Comprehensive diagnostic output for Vault troubleshooting.

This command collects and displays:
- Binary information (location, size, permissions, version)
- Configuration files and backups
- File/directory ownership and permissions
- Systemd service status and logs
- Network connectivity
- Process information
- Recent errors

Example:
  sudo eos debug vault
  sudo eos debug vault > vault-debug.txt`,
	RunE: eos_cli.Wrap(runDebugVault),
}

func init() {
	debugCmd.AddCommand(debugVaultCmd)
}

func runDebugVault(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Vault diagnostic collection")

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("VAULT DIAGNOSTIC REPORT")
	fmt.Println("Generated:", time.Now().Format(time.RFC3339))
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	// Section 1: Binary Information
	printSection("VAULT BINARY")
	checkBinary("/usr/local/bin/vault")
	checkBinary("/usr/bin/vault")

	// Check which vault is in PATH
	runCommand("which vault")
	runCommand("whereis vault")

	// Section 2: Version Information
	printSection("VERSION INFORMATION")
	runCommand("/usr/local/bin/vault version")
	runCommand("/usr/local/bin/vault --version")

	// Section 3: Configuration Files
	printSection("CONFIGURATION FILES")
	checkFileDetails("/etc/vault.d/vault.hcl")
	fmt.Println("\n--- Configuration Content ---")
	runCommand("cat /etc/vault.d/vault.hcl")

	// Check backups
	fmt.Println("\n--- Configuration Backups ---")
	runCommand("ls -lah /etc/vault.d/*.backup* 2>/dev/null || echo 'No backups found'")

	// Section 4: Directory Structure
	printSection("DIRECTORY STRUCTURE AND PERMISSIONS")
	checkDirectory("/etc/vault.d")
	checkDirectory("/opt/vault")
	checkDirectory("/opt/vault/data")
	checkDirectory("/var/log/vault")

	// Section 5: User and Group
	printSection("USER AND GROUP INFORMATION")
	runCommand("id vault")
	runCommand("groups vault")
	runCommand("grep vault /etc/passwd")
	runCommand("grep vault /etc/group")

	// Section 6: Systemd Service
	printSection("SYSTEMD SERVICE")
	checkFileDetails("/etc/systemd/system/vault.service")
	fmt.Println("\n--- Service File Content ---")
	runCommand("cat /etc/systemd/system/vault.service")

	fmt.Println("\n--- Service Status ---")
	runCommand("systemctl status vault.service --no-pager -l")

	fmt.Println("\n--- Service Properties ---")
	runCommand("systemctl show vault.service --no-pager")

	// Section 7: Logs
	printSection("SYSTEMD LOGS (Last 100 lines)")
	runCommand("journalctl -u vault.service -n 100 --no-pager")

	fmt.Println("\n--- Recent Errors ---")
	runCommand("journalctl -u vault.service -p err --no-pager -n 50")

	// Section 8: Process Information
	printSection("PROCESS INFORMATION")
	runCommand("ps aux | grep -i vault | grep -v grep")
	runCommand("pgrep -a vault")

	// Section 9: Network
	printSection("NETWORK INFORMATION")
	runCommand("ss -tlnp | grep vault")
	runCommand("ss -tlnp | grep 8200")
	runCommand("netstat -tlnp 2>/dev/null | grep 8200 || echo 'netstat not available'")

	fmt.Println("\n--- Network Connectivity Test ---")
	runCommand("curl -k -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8200/v1/sys/health || echo 'Failed'")
	runCommand("curl -k -s http://127.0.0.1:8200/v1/sys/health | head -c 500")

	// Section 10: File Capabilities
	printSection("BINARY CAPABILITIES")
	runCommand("getcap /usr/local/bin/vault")
	runCommand("ldd /usr/local/bin/vault | head -20")

	// Section 11: SELinux/AppArmor
	printSection("SECURITY MODULES")
	runCommand("getenforce 2>/dev/null || echo 'SELinux not installed'")
	runCommand("aa-status 2>/dev/null | grep vault || echo 'No AppArmor profile for vault'")

	// Section 12: Disk Space
	printSection("DISK SPACE")
	runCommand("df -h /opt/vault /etc/vault.d /var/log/vault 2>/dev/null")

	// Section 13: Recent System Logs
	printSection("RECENT SYSTEM ERRORS")
	runCommand("journalctl -p err -n 20 --no-pager --since '10 minutes ago'")

	// Section 14: Environment
	printSection("ENVIRONMENT VARIABLES")
	fmt.Println("VAULT_ADDR:", os.Getenv("VAULT_ADDR"))
	fmt.Println("VAULT_TOKEN:", maskToken(os.Getenv("VAULT_TOKEN")))
	fmt.Println("VAULT_CACERT:", os.Getenv("VAULT_CACERT"))
	fmt.Println("VAULT_SKIP_VERIFY:", os.Getenv("VAULT_SKIP_VERIFY"))

	// Section 15: Validation Test
	printSection("CONFIGURATION VALIDATION TEST")
	runCommand("/usr/local/bin/vault validate /etc/vault.d/vault.hcl")

	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("END OF DIAGNOSTIC REPORT")
	fmt.Println(strings.Repeat("=", 80))

	return nil
}

func printSection(title string) {
	fmt.Println()
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()
}

func checkBinary(path string) {
	fmt.Printf("\n--- Binary: %s ---\n", path)

	info, err := os.Stat(path)
	if err != nil {
		fmt.Printf("  Status: NOT FOUND (%v)\n", err)
		return
	}

	fmt.Printf("  Status: EXISTS\n")
	fmt.Printf("  Size: %d bytes (%.2f MB)\n", info.Size(), float64(info.Size())/1024/1024)
	fmt.Printf("  Permissions: %s\n", info.Mode().String())
	fmt.Printf("  Modified: %s\n", info.ModTime().Format("2006-01-02 15:04:05"))

	// Check if executable
	if info.Mode().Perm()&0111 != 0 {
		fmt.Println("  Executable: YES")
	} else {
		fmt.Println("  Executable: NO (missing execute permission)")
	}

	// Get file details
	runCommand(fmt.Sprintf("ls -lah %s", path))
	runCommand(fmt.Sprintf("file %s", path))
	runCommand(fmt.Sprintf("md5sum %s 2>/dev/null || md5 %s 2>/dev/null", path, path))
}

func checkDirectory(path string) {
	fmt.Printf("\n--- Directory: %s ---\n", path)

	info, err := os.Stat(path)
	if err != nil {
		fmt.Printf("  Status: NOT FOUND (%v)\n", err)
		return
	}

	if !info.IsDir() {
		fmt.Println("  Status: EXISTS BUT NOT A DIRECTORY")
		return
	}

	fmt.Printf("  Status: EXISTS\n")
	fmt.Printf("  Permissions: %s\n", info.Mode().String())
	fmt.Printf("  Modified: %s\n", info.ModTime().Format("2006-01-02 15:04:05"))

	// List contents with details
	runCommand(fmt.Sprintf("ls -lah %s", path))

	// Check ownership
	runCommand(fmt.Sprintf("stat %s", path))
}

func checkFileDetails(path string) {
	fmt.Printf("\n--- File: %s ---\n", path)

	info, err := os.Stat(path)
	if err != nil {
		fmt.Printf("  Status: NOT FOUND (%v)\n", err)
		return
	}

	fmt.Printf("  Status: EXISTS\n")
	fmt.Printf("  Size: %d bytes\n", info.Size())
	fmt.Printf("  Permissions: %s\n", info.Mode().String())
	fmt.Printf("  Modified: %s\n", info.ModTime().Format("2006-01-02 15:04:05"))

	runCommand(fmt.Sprintf("ls -lah %s", path))
	runCommand(fmt.Sprintf("stat %s", path))
}

func runCommand(cmdStr string) {
	fmt.Printf("\n$ %s\n", cmdStr)

	cmd := exec.Command("sh", "-c", cmdStr)
	output, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	fmt.Print(string(output))
}

func maskToken(token string) string {
	if token == "" {
		return "(not set)"
	}
	if len(token) <= 8 {
		return "***"
	}
	return token[:4] + "..." + token[len(token)-4:]
}
