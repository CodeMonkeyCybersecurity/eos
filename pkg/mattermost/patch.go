package mattermost

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PatchMattermostEnv copies and updates the .env file with Eos-standard values.
func PatchMattermostEnv(cloneDir string) error {
	src := filepath.Join(cloneDir, "env.example")
	dst := filepath.Join(cloneDir, ".env")

	// Only copy if not already present
	if _, err := os.Stat(dst); os.IsNotExist(err) {
		input, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read env.example: %w", err)
		}
		if err := os.WriteFile(dst, input, shared.ConfigFilePerm); err != nil {
			return fmt.Errorf("write .env: %w", err)
		}
	}

	// Patch domain and port
	return patchEnvInPlace(dst, DefaultEnvUpdates)
}

func patchEnvInPlace(path string, updates map[string]string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Log silently as this is a file operation utility
			_ = err
		}
	}()

	var newLines []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		for key, val := range updates {
			if strings.HasPrefix(line, key+"=") || strings.HasPrefix(line, "#"+key+"=") {
				line = fmt.Sprintf("%s=%s", key, val)
				break
			}
		}
		newLines = append(newLines, line)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return os.WriteFile(path, []byte(strings.Join(newLines, "\n")+"\n"), shared.ConfigFilePerm)
}
