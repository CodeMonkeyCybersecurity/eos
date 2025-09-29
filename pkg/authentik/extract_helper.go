// pkg/authentik/extract_helper.go

package authentik

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ExtractConfigurationAPI extracts Authentik configuration via API
func ExtractConfigurationAPI(ctx context.Context, baseURL, token string, types, apps, providers []string, includeSecrets bool) (*AuthentikConfig, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	config := &AuthentikConfig{
		Metadata: ConfigMetadata{
			ExportedAt: time.Now(),
			SourceURL:  baseURL,
			ExportedBy: "",
		},
		Providers:        []Provider{},
		Applications:     []Application{},
		PropertyMappings: []PropertyMapping{},
		Flows:            []Flow{},
		Stages:           []Stage{},
		Groups:           []Group{},
		Policies:         []Policy{},
		Certificates:     []Certificate{},
	}

	// Helper function to make API calls
	makeAPICall := func(endpoint string) ([]byte, error) {
		url := fmt.Sprintf("%s/api/v3/%s", strings.TrimSuffix(baseURL, "/"), endpoint)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("API request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
		}

		return io.ReadAll(resp.Body)
	}

	// Extract each type requested
	for _, resourceType := range types {
		switch strings.ToLower(resourceType) {
		case "providers":
			if data, err := makeAPICall("providers/all/"); err == nil {
				var result struct {
					Results []Provider `json:"results"`
				}
				if err := json.Unmarshal(data, &result); err == nil {
					config.Providers = filterProviders(result.Results, providers)
				}
			}

		case "applications":
			if data, err := makeAPICall("core/applications/"); err == nil {
				var result struct {
					Results []Application `json:"results"`
				}
				if err := json.Unmarshal(data, &result); err == nil {
					config.Applications = filterApplications(result.Results, apps)
				}
			}

		case "mappings", "property_mappings":
			if data, err := makeAPICall("propertymappings/all/"); err == nil {
				var result struct {
					Results []json.RawMessage `json:"results"`
				}
				if err := json.Unmarshal(data, &result); err == nil {
					// Parse SAML property mappings specifically
					for _, raw := range result.Results {
						var mapping PropertyMapping
						if err := json.Unmarshal(raw, &mapping); err == nil {
							config.PropertyMappings = append(config.PropertyMappings, mapping)
						}
					}
				}
			}

		case "flows":
			if data, err := makeAPICall("flows/instances/"); err == nil {
				var result struct {
					Results []Flow `json:"results"`
				}
				if err := json.Unmarshal(data, &result); err == nil {
					config.Flows = result.Results
				}
			}

		case "stages":
			if data, err := makeAPICall("stages/all/"); err == nil {
				var result struct {
					Results []Stage `json:"results"`
				}
				if err := json.Unmarshal(data, &result); err == nil {
					config.Stages = result.Results
				}
			}

		case "groups":
			if data, err := makeAPICall("core/groups/"); err == nil {
				var result struct {
					Results []Group `json:"results"`
				}
				if err := json.Unmarshal(data, &result); err == nil {
					config.Groups = result.Results
				}
			}

		case "policies":
			if data, err := makeAPICall("policies/all/"); err == nil {
				var result struct {
					Results []Policy `json:"results"`
				}
				if err := json.Unmarshal(data, &result); err == nil {
					config.Policies = result.Results
				}
			}

		case "certificates":
			endpoint := "crypto/certificatekeypairs/"
			if !includeSecrets {
				endpoint += "?exclude_key=true"
			}
			if data, err := makeAPICall(endpoint); err == nil {
				var result struct {
					Results []Certificate `json:"results"`
				}
				if err := json.Unmarshal(data, &result); err == nil {
					config.Certificates = result.Results
				}
			}
		}
	}

	// Try to get version info
	if data, err := makeAPICall("admin/version/"); err == nil {
		var versionInfo struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(data, &versionInfo); err == nil {
			config.Metadata.AuthentikVersion = versionInfo.Version
		}
	}

	return config, nil
}

// filterProviders filters providers by name if a filter list is provided
func filterProviders(providers []Provider, filter []string) []Provider {
	if len(filter) == 0 {
		return providers
	}

	filtered := []Provider{}
	filterMap := make(map[string]bool)
	for _, name := range filter {
		filterMap[strings.ToLower(name)] = true
	}

	for _, provider := range providers {
		if filterMap[strings.ToLower(provider.Name)] {
			filtered = append(filtered, provider)
		}
	}
	return filtered
}

// filterApplications filters applications by name if a filter list is provided
func filterApplications(apps []Application, filter []string) []Application {
	if len(filter) == 0 {
		return apps
	}

	filtered := []Application{}
	filterMap := make(map[string]bool)
	for _, name := range filter {
		filterMap[strings.ToLower(name)] = true
	}

	for _, app := range apps {
		lowerName := strings.ToLower(app.Name)
		lowerSlug := strings.ToLower(app.Slug)
		if filterMap[lowerName] || filterMap[lowerSlug] {
			filtered = append(filtered, app)
		}
	}
	return filtered
}