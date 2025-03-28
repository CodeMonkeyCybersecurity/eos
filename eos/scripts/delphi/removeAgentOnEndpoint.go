package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// uninstallMacos checks for the uninstall script on macOS and executes it with sudo.
func uninstallMacos() {
	uninstallScript := "/Library/Ossec/uninstall.sh"
	if _, err := os.Stat(uninstallScript); err == nil {
		fmt.Println("Found uninstall script at", uninstallScript)
		cmd := exec.Command("sudo", uninstallScript)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println("Error during macOS uninstallation:", err)
		} else {
			fmt.Println("Wazuh agent uninstalled successfully on macOS.")
		}
	} else {
		fmt.Println("Uninstall script not found at", uninstallScript)
		fmt.Println("Please verify the agent installation location.")
	}
}

// uninstallDeb removes the Wazuh agent package using apt-get purge.
func uninstallDeb() {
	fmt.Println("Attempting to uninstall Wazuh agent on a Debian-based system using apt-get purge...")
	cmd := exec.Command("sudo", "apt-get", "purge", "-y", "wazuh-agent")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println("Error during Debian-based uninstallation:", err)
	} else {
		fmt.Println("Wazuh agent uninstalled successfully on Debian-based system.")
	}
}

// uninstallRpm removes the Wazuh agent package using yum or dnf.
func uninstallRpm() {
	var pkgManager string
	if path, err := exec.LookPath("yum"); err == nil {
		pkgManager = path
	} else if path, err := exec.LookPath("dnf"); err == nil {
		pkgManager = path
	}

	if pkgManager != "" {
		fmt.Printf("Attempting to uninstall Wazuh agent on an RPM-based system using %s remove...\n", pkgManager)
		cmd := exec.Command("sudo", pkgManager, "remove", "-y", "wazuh-agent")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println("Error during RPM-based uninstallation:", err)
		} else {
			fmt.Println("Wazuh agent uninstalled successfully on RPM-based system.")
		}
	} else {
		fmt.Println("Neither yum nor dnf was found. Cannot uninstall Wazuh agent on this RPM-based system.")
	}
}

// uninstallWindows queries installed products via WMIC and uninstalls the Wazuh agent.
func uninstallWindows() {
	fmt.Println("Querying installed products for Wazuh agent...")
	// Build the WMIC query command.
	// Note: The command is executed via the shell.
	queryCmd := `wmic product where "Name like '%%Wazuh%%'" get IdentifyingNumber,Name`
	cmd := exec.Command("cmd", "/C", queryCmd)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println("Login request failed:", err)
		return
	}

	output := outBuf.String()
	fmt.Println("WMIC query output:")
	fmt.Println(output)

	scanner := bufio.NewScanner(strings.NewReader(output))
	lines := []string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	if len(lines) < 2 {
		fmt.Println("No Wazuh agent found via WMIC.")
		return
	}

	// The first line is a header; process subsequent lines.
	for _, line := range lines[1:] {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		productCode := parts[0]
		productName := strings.Join(parts[1:], " ")
		if strings.Contains(productName, "Wazuh") {
			fmt.Println("Found product:", productName, "with code:", productCode)
			uninstallCmd := fmt.Sprintf("msiexec /x %s /qn", productCode)
			fmt.Println("Uninstalling Wazuh agent using command:", uninstallCmd)
			// Execute the uninstall command via the shell.
			cmdUninstall := exec.Command("cmd", "/C", uninstallCmd)
			cmdUninstall.Stdout = os.Stdout
			cmdUninstall.Stderr = os.Stderr
			if err := cmdUninstall.Run(); err != nil {
				fmt.Println("Error during Windows uninstallation:", err)
			} else {
				fmt.Println("Wazuh agent uninstalled successfully from Windows.")
			}
			return
		}
	}
	fmt.Println("Wazuh agent product not found in WMIC output.")
}

func main() {
	currentOS := runtime.GOOS
	fmt.Println("Detected operating system:", currentOS)
	switch currentOS {
	case "darwin":
		uninstallMacos()
	case "linux":
		// Try reading /etc/os-release to decide whether to use Debian-based or RPM-based removal.
		data, err := ioutil.ReadFile("/etc/os-release")
		if err != nil {
			fmt.Println("Error reading /etc/os-release:", err)
			fmt.Println("Attempting Debian-based removal as fallback.")
			uninstallDeb()
			return
		}
		osRelease := strings.ToLower(string(data))
		if strings.Contains(osRelease, "debian") || strings.Contains(osRelease, "ubuntu") {
			uninstallDeb()
		} else if strings.Contains(osRelease, "rhel") || strings.Contains(osRelease, "centos") ||
			strings.Contains(osRelease, "fedora") || strings.Contains(osRelease, "suse") {
			uninstallRpm()
		} else {
			fmt.Println("Linux distribution not clearly identified; attempting Debian-based removal.")
			uninstallDeb()
		}
	case "windows":
		uninstallWindows()
	default:
		fmt.Println("Unsupported operating system:", currentOS)
	}
}
