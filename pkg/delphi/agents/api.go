package agents

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi/tls"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// FetchAgents retrieves agents from the Delphi API
// Migrated from cmd/create/delphi.go fetchAgents
func FetchAgents(rc *eos_io.RuntimeContext, baseURL, token string) (*AgentsResponse, error) {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS - Validate inputs
	log.Info("🔍 Assessing API fetch parameters",
		zap.String("base_url", baseURL))

	url := strings.TrimRight(baseURL, "/") + "/agents?select=id,os,version"

	// INTERVENE - Make API request
	log.Debug("🚀 Fetching agents from API", zap.String("url", url))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tls.GetAgentFetchTLSConfig(),
		},
	}

	req, err := http.NewRequestWithContext(rc.Ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// EVALUATE - Parse and validate response
	log.Debug("📊 Parsing API response", zap.Int("status_code", resp.StatusCode))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var parsed AgentsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	log.Info(" Successfully fetched agents",
		zap.Int("agent_count", len(parsed.Data.AffectedItems)))

	return &parsed, nil
}
