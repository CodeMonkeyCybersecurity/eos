package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AuthentikClient represents a client for Authentik API
type AuthentikClient struct {
	client  *http.Client
	baseURL string
	token   string
	ctx     context.Context
}

// AuthentikUser represents a user in Authentik
type AuthentikUser struct {
	UUID     string   `json:"pk"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	IsActive bool     `json:"is_active"`
	Groups   []string `json:"groups"`
}

// AuthentikGroup represents a group in Authentik
type AuthentikGroup struct {
	UUID        string `json:"pk"`
	Name        string `json:"name"`
	IsSuperuser bool   `json:"is_superuser"`
	UsersCount  int    `json:"users_obj_count"`
	NumUsers    int    `json:"num_pk"`
}

// AuthentikEvent represents an event in Authentik
type AuthentikEvent struct {
	UUID      string                 `json:"pk"`
	User      map[string]interface{} `json:"user"`
	Action    string                 `json:"action"`
	Result    string                 `json:"result"`
	Timestamp time.Time              `json:"created"`
	ClientIP  string                 `json:"client_ip"`
	Context   map[string]interface{} `json:"context"`
}

// AuthentikPaginatedResponse represents a paginated response from Authentik
type AuthentikPaginatedResponse[T any] struct {
	Pagination struct {
		Next     *string `json:"next"`
		Previous *string `json:"previous"`
		Count    int     `json:"count"`
	} `json:"pagination"`
	Results []T `json:"results"`
}

// Ensure AuthentikClient implements AuthClient interface
var _ AuthClient = (*AuthentikClient)(nil)

// NewAuthentikClient creates a new Authentik client
func NewAuthentikClient(baseURL, token string) (*AuthentikClient, error) {
	if baseURL == "" || token == "" {
		return nil, fmt.Errorf("baseURL and token are required")
	}

	ctx := context.Background()
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	return &AuthentikClient{
		client:  client,
		baseURL: baseURL,
		token:   token,
		ctx:     ctx,
	}, nil
}

// makeRequest makes an HTTP request to the Authentik API
func (c *AuthentikClient) makeRequest(method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(c.ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

// GetUsers retrieves users from Authentik
func (c *AuthentikClient) GetUsers(search string) ([]AuthentikUser, error) {
	path := "/api/v3/core/users/"
	if search != "" {
		path += "?search=" + search
	}

	resp, err := c.makeRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	// SECURITY P2 #8: Check defer Body.Close() error
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Logger not available in this context, silently ignore (HTTP client best practice)
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get users: %s - %s", resp.Status, string(body))
	}

	var paginatedResp AuthentikPaginatedResponse[AuthentikUser]
	if err := json.NewDecoder(resp.Body).Decode(&paginatedResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return paginatedResp.Results, nil
}

// GetUserByUsername retrieves a specific user by username
func (c *AuthentikClient) GetUserByUsername(username string) (*AuthentikUser, error) {
	users, err := c.GetUsers(username)
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		if user.Username == username {
			return &user, nil
		}
	}

	return nil, fmt.Errorf("user not found: %s", username)
}

// GetGroups retrieves groups from Authentik
func (c *AuthentikClient) GetGroups(search string) ([]AuthentikGroup, error) {
	path := "/api/v3/core/groups/"
	if search != "" {
		path += "?search=" + search
	}

	resp, err := c.makeRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	// SECURITY P2 #8: Check defer Body.Close() error
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Logger not available in this context, silently ignore (HTTP client best practice)
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get groups: %s - %s", resp.Status, string(body))
	}

	var paginatedResp AuthentikPaginatedResponse[AuthentikGroup]
	if err := json.NewDecoder(resp.Body).Decode(&paginatedResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return paginatedResp.Results, nil
}

// GroupExists checks if a group exists in Authentik
func (c *AuthentikClient) GroupExists(groupName string) (bool, error) {
	groups, err := c.GetGroups(groupName)
	if err != nil {
		return false, fmt.Errorf("failed to fetch groups: %w", err)
	}

	for _, group := range groups {
		if group.Name == groupName {
			return true, nil
		}
	}

	return false, nil
}

// CreateGroup creates a new group in Authentik
func (c *AuthentikClient) CreateGroup(groupName string) error {
	body := map[string]interface{}{
		"name":         groupName,
		"is_superuser": false,
	}

	resp, err := c.makeRequest("POST", "/api/v3/core/groups/", body)
	if err != nil {
		return err
	}
	// SECURITY P2 #8: Check defer Body.Close() error
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Logger not available in this context, silently ignore (HTTP client best practice)
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create group: %s - %s", resp.Status, string(respBody))
	}

	return nil
}

// AddUserToGroup adds a user to a group in Authentik
func (c *AuthentikClient) AddUserToGroup(username, groupName string) error {
	// First, get the user
	user, err := c.GetUserByUsername(username)
	if err != nil {
		return fmt.Errorf("failed to find user %s: %w", username, err)
	}

	// Get the group
	groups, err := c.GetGroups(groupName)
	if err != nil {
		return fmt.Errorf("failed to fetch groups: %w", err)
	}

	var targetGroup *AuthentikGroup
	for _, group := range groups {
		if group.Name == groupName {
			targetGroup = &group
			break
		}
	}

	if targetGroup == nil {
		return fmt.Errorf("group not found: %s", groupName)
	}

	// Add user to group by updating user's groups
	// Ensure we don't duplicate group assignments (idempotent call)
	for _, existing := range user.Groups {
		if existing == targetGroup.UUID {
			return nil
		}
	}

	body := map[string]interface{}{
		"groups": append(user.Groups, targetGroup.UUID),
	}

	resp, err := c.makeRequest("PATCH", "/api/v3/core/users/"+user.UUID+"/", body)
	if err != nil {
		return err
	}
	// SECURITY P2 #8: Check defer Body.Close() error
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Logger not available in this context, silently ignore (HTTP client best practice)
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to add user to group: %s - %s", resp.Status, string(respBody))
	}

	return nil
}

// GetEvents retrieves events from Authentik (equivalent to registration events)
func (c *AuthentikClient) GetEvents(action string, since time.Time) ([]AuthentikEvent, error) {
	path := "/api/v3/events/events/"
	if action != "" {
		path += "?action=" + action
	}

	resp, err := c.makeRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	// SECURITY P2 #8: Check defer Body.Close() error
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Logger not available in this context, silently ignore (HTTP client best practice)
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get events: %s - %s", resp.Status, string(body))
	}

	var paginatedResp AuthentikPaginatedResponse[AuthentikEvent]
	if err := json.NewDecoder(resp.Body).Decode(&paginatedResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Filter events by timestamp
	var filtered []AuthentikEvent
	for _, event := range paginatedResp.Results {
		if event.Timestamp.After(since) {
			filtered = append(filtered, event)
		}
	}

	return filtered, nil
}

// GetRegistrationEvents retrieves user registration events
func (c *AuthentikClient) GetRegistrationEvents(since time.Time) ([]AuthentikEvent, error) {
	return c.GetEvents("user_write", since)
}

// Health checks if the Authentik API is accessible and responding
func (c *AuthentikClient) Health() error {
	resp, err := c.makeRequest("GET", "/api/v3/", nil)
	if err != nil {
		return fmt.Errorf("authentik API not responding: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Logger not available in this context, silently ignore (HTTP client best practice)
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentik API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetVersion retrieves the Authentik version information
func (c *AuthentikClient) GetVersion() (string, error) {
	resp, err := c.makeRequest("GET", "/api/v3/root/config/", nil)
	if err != nil {
		return "", fmt.Errorf("failed to get version: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Logger not available in this context, silently ignore (HTTP client best practice)
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get version: %s - %s", resp.Status, string(body))
	}

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", fmt.Errorf("failed to decode version response: %w", err)
	}

	if version, ok := config["version"].(string); ok {
		return version, nil
	}

	return "unknown", nil
}

// CreateUser creates a new user in Authentik
func (c *AuthentikClient) CreateUser(username, name, email, password string) (*AuthentikUser, error) {
	body := map[string]interface{}{
		"username":  username,
		"name":      name,
		"email":     email,
		"password":  password,
		"is_active": true,
	}

	resp, err := c.makeRequest("POST", "/api/v3/core/users/", body)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create user: %s - %s", resp.Status, string(respBody))
	}

	var user AuthentikUser
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if err := json.Unmarshal(respBody, &user); err != nil {
		return nil, fmt.Errorf("failed to decode user response: %w", err)
	}

	return &user, nil
}
