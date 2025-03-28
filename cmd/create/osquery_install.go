package create

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// getOSID reads /etc/os-release and returns the OS ID (e.g. "ubuntu", "debian")
func getOSID() (string, error) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var osID string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID=") {
			osID = strings.TrimPrefix(line, "ID=")
			osID = strings.Trim(osID, `"`)
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return osID, nil
}

func runCommand(name string, args ...string) {
	fmt.Printf("Running: %s %v\n", name, args)
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Command %s failed with %v", name, err)
	}
}

func addRepo(arch string) {
	// Build the repository line using the provided arch value.
	repoLine := fmt.Sprintf("deb [arch=%s signed-by=/etc/apt/keyrings/osquery.asc] https://pkg.osquery.io/deb deb main", arch)
	// Write the repoLine to /etc/apt/sources.list.d/osquery.list
	cmd := exec.Command("sudo", "sh", "-c", fmt.Sprintf("echo '%s' > /etc/apt/sources.list.d/osquery.list", repoLine))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Println("Adding repository by writing to /etc/apt/sources.list.d/osquery.list")
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to add repository: %v", err)
	}
}

func installOsquery(arch string) {
	// Step 1: Create keyrings directory
	runCommand("sudo", "mkdir", "-p", "/etc/apt/keyrings")

	// Step 2: Download and save the osquery GPG key.
	curlCmd := exec.Command("curl", "-L", "https://pkg.osquery.io/deb/pubkey.gpg")
	var curlOutput bytes.Buffer
	curlCmd.Stdout = &curlOutput
	curlCmd.Stderr = os.Stderr
	if err := curlCmd.Run(); err != nil {
		log.Fatalf("Failed to download key: %v", err)
	}

	teeCmd := exec.Command("sudo", "tee", "/etc/apt/keyrings/osquery.asc")
	teeCmd.Stdin = &curlOutput
	teeCmd.Stdout = os.Stdout
	teeCmd.Stderr = os.Stderr
	if err := teeCmd.Run(); err != nil {
		log.Fatalf("Failed to write key: %v", err)
	}

	// Step 3: Add the osquery repository using the correct architecture.
	addRepo(arch)

	// Step 4: Update package list and install osquery.
	runCommand("sudo", "apt", "update")
	runCommand("sudo", "apt", "install", "-y", "osquery")
}

func main() {
	// Detect OS.
	osID, err := getOSID()
	if err != nil {
		log.Fatalf("Could not determine OS: %v", err)
	}
	fmt.Printf("Detected OS: %s\n", osID)

	// Detect architecture using Go's runtime package.
	arch := runtime.GOARCH
	fmt.Printf("Detected Architecture: %s\n", arch)

	// Allow only amd64 or arm64.
	if arch != "amd64" && arch != "arm64" {
		log.Fatalf("Architecture %s is not supported by this script. Only amd64 and arm64 are supported.", arch)
	}

	// Proceed only if OS is Ubuntu or Debian.
	switch osID {
	case "ubuntu", "debian":
		installOsquery(arch)
	default:
		log.Fatalf("OS %s is not supported by this script. Only Ubuntu and Debian are supported.", osID)
	}
}
