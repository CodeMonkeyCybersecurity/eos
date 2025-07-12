// pkg/jenkins/api.go

package jenkins

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client represents a Jenkins API client
type Client struct {
	BaseURL    string
	Username   string
	APIToken   string
	HTTPClient *http.Client
}

// NewClient creates a new Jenkins client
func NewClient(baseURL, username, apiToken string) *Client {
	return &Client{
		BaseURL:  baseURL,
		Username: username,
		APIToken: apiToken,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// doRequest handles the common logic for all API requests
func (c *Client) doRequest(method, path string, body interface{}) ([]byte, error) {
	// Build the full URL
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}
	u.Path = path

	// Prepare the request body if provided
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	// Create the request
	req, err := http.NewRequest(method, u.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication and headers
	req.SetBasicAuth(c.Username, c.APIToken)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read the response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for HTTP errors
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// Job represents a Jenkins job
type Job struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Color       string `json:"color"`
	Buildable   bool   `json:"buildable"`
	LastBuild   *Build `json:"lastBuild"`
	InQueue     bool   `json:"inQueue"`
	Description string `json:"description"`
}

// Build represents a Jenkins build
type Build struct {
	Number    int    `json:"number"`
	URL       string `json:"url"`
	Result    string `json:"result"`
	Timestamp int64  `json:"timestamp"`
	Duration  int64  `json:"duration"`
	Building  bool   `json:"building"`
}

// GetJob retrieves information about a specific job
func (c *Client) GetJob(jobName string) (*Job, error) {
	path := fmt.Sprintf("/job/%s/api/json", jobName)
	respBody, err := c.doRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var job Job
	if err := json.Unmarshal(respBody, &job); err != nil {
		return nil, fmt.Errorf("failed to parse job response: %w", err)
	}

	return &job, nil
}

// BuildParameters represents parameters for triggering a build
type BuildParameters map[string]interface{}

// TriggerBuild starts a new build for a job
func (c *Client) TriggerBuild(jobName string, params BuildParameters) error {
	path := fmt.Sprintf("/job/%s/build", jobName)

	if len(params) > 0 {
		// If we have parameters, use the buildWithParameters endpoint
		path = fmt.Sprintf("/job/%s/buildWithParameters", jobName)

		// Jenkins expects form data for parameters
		values := url.Values{}
		for key, value := range params {
			values.Set(key, fmt.Sprintf("%v", value))
		}

		// For parameters, we need to use form encoding
		req, err := http.NewRequest("POST", c.BaseURL+path, bytes.NewBufferString(values.Encode()))
		if err != nil {
			return err
		}

		req.SetBasicAuth(c.Username, c.APIToken)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("failed to trigger build (status %d): %s", resp.StatusCode, string(body))
		}

		return nil
	}

	// For builds without parameters, just POST to the build endpoint
	_, err := c.doRequest("POST", path, nil)
	return err
}

// WaitForBuild waits for a build to complete and returns its result
func (c *Client) WaitForBuild(jobName string, buildNumber int, timeout time.Duration) (*Build, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		path := fmt.Sprintf("/job/%s/%d/api/json", jobName, buildNumber)
		respBody, err := c.doRequest("GET", path, nil)
		if err != nil {
			// Build might not exist yet if we're checking too quickly
			time.Sleep(2 * time.Second)
			continue
		}

		var build Build
		if err := json.Unmarshal(respBody, &build); err != nil {
			return nil, fmt.Errorf("failed to parse build response: %w", err)
		}

		if !build.Building {
			return &build, nil
		}

		time.Sleep(5 * time.Second)
	}

	return nil, fmt.Errorf("timeout waiting for build to complete")
}
