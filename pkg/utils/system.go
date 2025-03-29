// pkg/utils/system.go

package utils

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

//
//---------------------------- SYSTEM INFO ---------------------------- //
//

// GetInternalHostname returns the machine's hostname.
// If os.Hostname() fails, it logs the error and returns "localhost".
func GetInternalHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	return hostname
}

// GetUbuntuCodename reads /etc/os-release and returns UBUNTU_CODENAME or VERSION_CODENAME
func GetUbuntuCodename() string {
	file, _ := os.Open("/etc/os-release")
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var codename string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "UBUNTU_CODENAME=") {
			codename = strings.TrimPrefix(line, "UBUNTU_CODENAME=")
			break
		}
		if strings.HasPrefix(line, "VERSION_CODENAME=") && codename == "" {
			codename = strings.TrimPrefix(line, "VERSION_CODENAME=")
		}
	}
	if codename == "" {
		fmt.Fprintln(os.Stderr, "Could not determine Ubuntu codename.")
		os.Exit(1)
	}
	return codename
}

// GetArchitecture returns the result of `dpkg --print-architecture`
func GetArchitecture() string {
	out, err := exec.Command("dpkg", "--print-architecture").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to detect architecture: %v\n", err)
		os.Exit(1)
	}
	return strings.TrimSpace(string(out))
}
