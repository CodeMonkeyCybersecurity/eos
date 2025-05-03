// pkg/utils/utils.go

package utils

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

//
//---------------------------- DEPLOY COMMANDS ---------------------------- //
//

// DeployApp deploys the application by copying necessary config files and restarting services
func DeployApp(app string, force bool) error {

	if err := ValidateConfigPaths(app); err != nil {
		return fmt.Errorf("failed to validate config paths: %w", err)
	}

	// Test Nginx configuration
	cmdTest := exec.Command("nginx", "-t")
	if output, err := cmdTest.CombinedOutput(); err != nil {
		return fmt.Errorf("nginx config test failed: %s", string(output))
	}

	// Restart Nginx
	cmdRestart := exec.Command("sudo", "systemctl", "restart", "nginx")
	if err := cmdRestart.Run(); err != nil {
		return fmt.Errorf("failed to restart nginx: %w", err)
	}

	return nil
}

func OrganizeAssetsForDeployment(app string) error {
	assetsDir := "assets"
	otherDir := "other" // "other" is at the project root

	// Ensure the "other" directory exists.
	if err := os.MkdirAll(otherDir, shared.DirPermStandard); err != nil {
		return fmt.Errorf("failed to create 'other' directory: %w", err)
	}

	// Define the generic allowed filenames (lowercase).
	allowedGenerics := map[string]bool{
		"http.conf":   true,
		"stream.conf": true,
		"nginx.conf":  true,
	}

	// Walk the assets directory.
	err := filepath.Walk(assetsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories.
		if info.IsDir() {
			return nil
		}

		// Compute the file's relative path from assetsDir.
		relPath, err := filepath.Rel(assetsDir, path)
		if err != nil {
			return err
		}

		// Get the base filename in lowercase.
		base := strings.ToLower(filepath.Base(path))

		// Check if the file is relevant.
		if allowedGenerics[base] || strings.Contains(base, strings.ToLower(app)) {
			return nil
		}

		// File is not relevant; log that it will be moved.
		dest := filepath.Join(otherDir, relPath)

		// Ensure the destination directory exists.
		if err := os.MkdirAll(filepath.Dir(dest), shared.DirPermStandard); err != nil {
			return fmt.Errorf("failed to create destination directory %s: %w", filepath.Dir(dest), err)
		}

		// Move (rename) the file.
		if err := os.Rename(path, dest); err != nil {
			return fmt.Errorf("failed to move file %s to %s: %w", path, dest, err)
		}

		return nil
	})
	return err
}

func ReplaceTokensInAllFiles(rootDir, baseDomain, backendIP string) error {
	return filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Read the file
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", path, err)
		}
		content := string(data)
		// Replace tokens
		content = strings.ReplaceAll(content, "${BASE_DOMAIN}", baseDomain)
		content = strings.ReplaceAll(content, "${backendIP}", backendIP)
		content = strings.ReplaceAll(content, "${BACKEND_IP}", backendIP)
		// Write the file back with the same permissions
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("failed to stat file %s: %w", path, err)
		}
		if err := os.WriteFile(path, []byte(content), info.Mode()); err != nil {
			return fmt.Errorf("failed to write file %s: %w", path, err)
		}
		return nil
	})
}

//
//---------------------------- DEPLOY HELPERS ---------------------------- //
//

// quote adds quotes around a string for cleaner logging
func Quote(s string) string {
	return fmt.Sprintf("%q", s)
}

// ValidateConfigPaths checks that the app’s Nginx source config files exist
func ValidateConfigPaths(app string) error {

	httpSrc := filepath.Join("assets/servers", app+".conf")

	if _, err := os.Stat(httpSrc); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("missing HTTP config: %s", httpSrc)
		}
		return fmt.Errorf("error checking config file: %w", err)
	}

	// Stream config is optional — no error if missing
	return nil
}

func SplitLines(s string) []string {
	scanner := bufio.NewScanner(strings.NewReader(s))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func JoinLines(lines []string) string {
	return strings.Join(lines, "\n")
}
