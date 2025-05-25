// pkg/unix/check.go
package eos_unix

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

func CheckSystemBinaries() error {
	_, err1 := exec.LookPath("sudo")
	_, err2 := exec.LookPath("bash")
	if err1 != nil || err2 != nil {
		return fmt.Errorf("missing required system binaries: sudo (%v), bash (%v)", err1, err2)
	}
	return nil
}

// Exists returns true if the file or directory at the given path exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}

// LookupUser returns the UID and GID of the given user with structured logging.
func LookupUser(name string) (int, int, error) {
	zap.L().Named("system")

	zap.L().Debug("🔍 Looking up user", zap.String("username", name))

	u, err := user.Lookup(name)
	if err != nil {
		zap.L().Error("❌ User lookup failed", zap.String("username", name), zap.Error(err))
		return 0, 0, fmt.Errorf("user lookup failed: %w", err)
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		zap.L().Error("❌ Invalid UID format", zap.String("uid", u.Uid), zap.Error(err))
		return 0, 0, fmt.Errorf("invalid UID: %w", err)
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		zap.L().Error("❌ Invalid GID format", zap.String("gid", u.Gid), zap.Error(err))
		return 0, 0, fmt.Errorf("invalid GID: %w", err)
	}

	zap.L().Info("✅ User lookup succeeded",
		zap.String("username", name),
		zap.Int("uid", uid),
		zap.Int("gid", gid),
		zap.String("home", u.HomeDir),
	)

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

	file, _ := os.Open("/etc/os-release")
	defer func() {
		if err := file.Close(); err != nil {
			zap.L().Warn("Failed to close log file", zap.Error(err))
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
