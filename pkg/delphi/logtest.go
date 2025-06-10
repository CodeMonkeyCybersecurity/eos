// pkg/delphi/logtest.go

package delphi

import (
	"encoding/json"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// CreateLogtestSession creates a logtest session and analyzes a provided log.
// logFormat can be "syslog", "apache", etc.
func CreateLogtestSession(rc *eos_io.RuntimeContext, cfg *Config, token, event, logFormat, location string) (*LogtestResponse, error) {
	payload := map[string]string{
		"event":      event,
		"log_format": logFormat,
		"location":   location,
	}

	respBytes, err := makeRequest(rc, cfg, token, "PUT", "/logtest", nil, payload)
	if err != nil {
		return nil, err
	}

	var logtestResp LogtestResponse
	if err := json.Unmarshal(respBytes, &logtestResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal logtest response: %w", err)
	}

	return &logtestResp, nil
}
