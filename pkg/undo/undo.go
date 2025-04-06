package undo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Define your Action type here if not already defined elsewhere
type Action struct {
	Type                string      `json:"type"`
	Target              string      `json:"target"`
	PreviousPermissions os.FileMode `json:"previous_permissions,omitempty"`
	BackupPath          string      `json:"backup_path,omitempty"`
}

var actions []Action

func LogAction(action Action) {
	actions = append(actions, action)
}

func GetActionLogDir() string {
	var candidates []string
	switch runtime.GOOS {
	case "linux":
		candidates = []string{
			filepath.Join(os.Getenv("XDG_STATE_HOME"), "eos", "actions"),
			"/var/lib/eos/actions",
			filepath.Join(os.Getenv("HOME"), ".local", "state", "eos", "actions"),
			"/tmp/eos/actions",
			"./eos-actions",
		}
	case "darwin":
		candidates = []string{
			filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "eos", "actions"),
			"/tmp/eos/actions",
			"./eos-actions",
		}
	case "windows":
		candidates = []string{
			filepath.Join(os.Getenv("LOCALAPPDATA"), "eos", "actions"),
			filepath.Join(os.Getenv("APPDATA"), "eos", "actions"),
			"./eos-actions",
		}
	default:
		candidates = []string{"./eos-actions"}
	}

	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0755); err == nil {
			return dir
		}
	}
	return "./eos-actions"
}

// SaveActionLog writes current actions to a timestamped file + latest.json
func SaveActionLog() error {
	dir := GetActionLogDir()

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
	_ = os.WriteFile(latest, data, 0644)

	return nil
}

// LoadActions loads a list of actions from a JSON file
func LoadActions(path string) ([]Action, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read action log: %w", err)
	}
	var loaded []Action
	if err := json.Unmarshal(data, &loaded); err != nil {
		return nil, fmt.Errorf("failed to parse action log: %w", err)
	}
	return loaded, nil
}

// ApplyUndo attempts to reverse the effects of a single action
func ApplyUndo(action Action) error {
	// 🧪 This is a stub — extend this logic as needed for your actions
	switch action.Type {
	case "delete_file":
		return os.Remove(action.Target)
	case "create_file":
		// Reverse of "create_file" would be to delete it
		return os.Remove(action.Target)
	case "mkdir":
		return os.Remove(action.Target)
	case "chmod":
		// Future: restore previous permissions
		return fmt.Errorf("undo for chmod not implemented yet")
	default:
		return fmt.Errorf("unknown undo action type: %s", action.Type)
	}
}
