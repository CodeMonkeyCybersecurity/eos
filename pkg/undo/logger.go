package undo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var actions []Action

func LogAction(action Action) {
	actions = append(actions, action)
}

// Call this at the end of each successful command
func SaveActionLog() error {
	dir := "/var/lib/eos/actions"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create actions dir: %w", err)
	}

	timestamp := time.Now().Format("2006-01-02T15-04-05")
	path := filepath.Join(dir, fmt.Sprintf("%s.json", timestamp))
	latest := filepath.Join(dir, "latest.json")

	data, err := json.MarshalIndent(actions, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode actions: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write action log: %w", err)
	}
	_ = os.WriteFile(latest, data, 0644) // symlink alternative for quick lookup

	return nil
}
