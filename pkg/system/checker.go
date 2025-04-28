/* pkg/system/checker.go */
package system

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"go.uber.org/zap"
)

// Exists returns true if the file or directory at the given path exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}

// LookupUser returns the UID and GID of the given user.
func LookupUser(name string) (int, int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("user lookup failed: %w", err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid UID: %w", err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid GID: %w", err)
	}
	return uid, gid, nil
}

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

/**/

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
	log := logger.GetLogger()
	file, _ := os.Open("/etc/os-release")
	defer func() {
		if err := file.Close(); err != nil {
			log.Warn("Failed to close log file", zap.Error(err))
		}
	}()

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
