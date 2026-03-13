// patch.go - .env file patching for Mattermost Docker Compose deployments.

package mattermost

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PatchMattermostEnv copies env.example to .env and applies Eos-standard overrides.
// Idempotent: only copies env.example if .env doesn't already exist.
func PatchMattermostEnv(baseDir string) error {
	src := filepath.Join(baseDir, EnvExampleFileName)
	dst := filepath.Join(baseDir, EnvFileName)

	// Only copy if not already present
	if _, err := os.Stat(dst); os.IsNotExist(err) {
		input, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read %s: %w", EnvExampleFileName, err)
		}
		if err := os.WriteFile(dst, input, EnvFilePerm); err != nil {
			return fmt.Errorf("write %s: %w", EnvFileName, err)
		}
	}

	return patchEnvInPlace(dst, DefaultEnvOverrides)
}

// patchEnvInPlace reads an .env file and replaces matching key=value lines.
// Both active (KEY=value) and commented (#KEY=value) lines are matched.
// Keys not found in the file are appended at the end.
func patchEnvInPlace(path string, updates map[string]string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	var newLines []string
	scanner := bufio.NewScanner(file)

	// Track which keys were found and replaced
	applied := make(map[string]bool, len(updates))
	for scanner.Scan() {
		line := scanner.Text()
		for key, val := range updates {
			if strings.HasPrefix(line, key+"=") || strings.HasPrefix(line, "#"+key+"=") {
				line = fmt.Sprintf("%s=%s", key, val)
				applied[key] = true
				break
			}
		}
		newLines = append(newLines, line)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}

	// Append any keys that weren't found in the existing file
	for key, val := range updates {
		if !applied[key] {
			newLines = append(newLines, fmt.Sprintf("%s=%s", key, val))
		}
	}

	return os.WriteFile(path, []byte(strings.Join(newLines, "\n")+"\n"), EnvFilePerm)
}
