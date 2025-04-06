// pkg/eosio/json.go

package vault

import (
	"encoding/json"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
)

// ReadJSON reads a JSON secret from Vault at the given path
func ReadVaultJSON(path string, out any) error {
	cmd := execute.ExecuteRaw("vault", "kv", "get", "-format=json", path)
	outBytes, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("vault read failed: %w", err)
	}

	var raw struct {
		Data struct {
			Data json.RawMessage `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(outBytes, &raw); err != nil {
		return fmt.Errorf("unmarshal vault json: %w", err)
	}
	return json.Unmarshal(raw.Data.Data, out)
}

// WriteJSON writes a JSON object to Vault at the given path
func WriteVaultJSON(path string, in any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}

	// Flatten JSON to key=value pairs
	var flat map[string]interface{}
	if err := json.Unmarshal(b, &flat); err != nil {
		return fmt.Errorf("flatten json: %w", err)
	}

	args := []string{"kv", "put", path}
	for k, v := range flat {
		args = append(args, fmt.Sprintf("%s=%v", k, v))
	}

	cmd := execute.ExecuteRaw("vault", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("vault write failed: %w\nOutput: %s", err, string(output))
	}
	return nil
}
