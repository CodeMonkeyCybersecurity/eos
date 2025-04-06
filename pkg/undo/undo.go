// pkg/undo/undo.go

package undo

import (
	"fmt"
	"os"
	"encoding/json"
)

type Action struct {
	Type   string `json:"type"`
	Target string `json:"target"`
	Backup string `json:"backup,omitempty"`
	Extra  map[string]string `json:"extra,omitempty"`
}

func LoadActions(path string) ([]Action, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var actions []Action
	if err := json.Unmarshal(data, &actions); err != nil {
		return nil, fmt.Errorf("failed to parse actions: %w", err)
	}
	return actions, nil
}

func ApplyUndo(action Action) error {
	switch action.Type {
	case "mask_systemd":
		return run("systemctl", "unmask", action.Target)
	case "patch_file":
		return os.Rename(action.Backup, action.Target)
	case "delete_file":
		return os.Remove(action.Target)
	// Add more reversible actions here
	default:
		return fmt.Errorf("unknown action type: %s", action.Type)
	}
}

func run(cmd string, args ...string) error {
	fmt.Printf("⚙️  Running: %s %v\n", cmd, args)
	return nil // Replace with exec.Command(cmd, args...).Run() in live mode
}
