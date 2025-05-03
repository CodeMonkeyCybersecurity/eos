// pkg/system/crontab.go
package system

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func GetCrontab() (string, error) {
	cmd := exec.Command("sudo", "crontab", "-l")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		if strings.Contains(err.Error(), "no crontab for") {
			return "", nil // normal empty state
		}
		return "", err // real failure
	}
	return out.String(), nil
}

func BackupCrontab(content string) (string, error) {
	timestamp := time.Now().Format("20060102-150405")
	path := fmt.Sprintf("crontab.backup.%s", timestamp)
	err := os.WriteFile(path, []byte(content), 0644)
	return path, err
}

func PatchMailto(crontab, email string) string {
	lines := strings.Split(crontab, "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "MAILTO=") {
			lines[i] = "MAILTO=" + email
			found = true
			break
		}
	}
	if !found {
		lines = append([]string{"MAILTO=" + email}, lines...)
	}
	return strings.Join(lines, "\n")
}

func SetCrontab(content string) error {
	cmd := exec.Command("sudo", "crontab", "-")
	cmd.Stdin = strings.NewReader(content)
	return cmd.Run()
}
