// pkg/authentik/users.go
// User management for Authentik
// CONSOLIDATION: Migrated from authentik_client.go to use unified Client

package authentik

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// User represents a user in Authentik
type User struct {
	UUID     string   `json:"pk"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	IsActive bool     `json:"is_active"`
	Groups   []string `json:"groups"`
}

// Note: Group type is defined in extract.go

// Event represents an event in Authentik
type Event struct {
	UUID      string                 `json:"pk"`
	User      map[string]interface{} `json:"user"`
	Action    string                 `json:"action"`
	Result    string                 `json:"result"`
	Timestamp time.Time              `json:"created"`
	ClientIP  string                 `json:"client_ip"`
	Context   map[string]interface{} `json:"context"`
}

// PaginatedResponse represents a paginated response from Authentik
type PaginatedResponse[T any] struct {
	Pagination struct {
		Next     *string `json:"next"`
		Previous *string `json:"previous"`
		Count    int     `json:"count"`
	} `json:"pagination"`
	Results []T `json:"results"`
}

// GetUsers retrieves users from Authentik
func (c *Client) GetUsers(ctx context.Context, search string) ([]User, error) {
	path := "/core/users/"
	if search != "" {
		path += "?search=" + search
	}

	data, err := c.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}

	var paginatedResp PaginatedResponse[User]
	if err := json.Unmarshal(data, &paginatedResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return paginatedResp.Results, nil
}

// GetUserByUsername retrieves a specific user by username
func (c *Client) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	users, err := c.GetUsers(ctx, username)
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

// CreateUser creates a new user in Authentik
func (c *Client) CreateUser(ctx context.Context, username, name, email, password string) (*User, error) {
	body := map[string]interface{}{
		"username":  username,
		"name":      name,
		"email":     email,
		"password":  password,
		"is_active": true,
	}

	data, err := c.Post(ctx, "/core/users/", body)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, fmt.Errorf("failed to decode user response: %w", err)
	}

	return &user, nil
}

// GetGroups retrieves groups from Authentik
func (c *Client) GetGroups(ctx context.Context, search string) ([]Group, error) {
	path := "/core/groups/"
	if search != "" {
		path += "?search=" + search
	}

	data, err := c.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get groups: %w", err)
	}

	var paginatedResp PaginatedResponse[Group]
	if err := json.Unmarshal(data, &paginatedResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return paginatedResp.Results, nil
}

// GroupExists checks if a group exists in Authentik
func (c *Client) GroupExists(ctx context.Context, groupName string) (bool, error) {
	groups, err := c.GetGroups(ctx, groupName)
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
func (c *Client) CreateGroup(ctx context.Context, groupName string) error {
	body := map[string]interface{}{
		"name":         groupName,
		"is_superuser": false,
	}

	_, err := c.Post(ctx, "/core/groups/", body)
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}

	return nil
}

// AddUserToGroup adds a user to a group in Authentik
func (c *Client) AddUserToGroup(ctx context.Context, username, groupName string) error {
	// First, get the user
	user, err := c.GetUserByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("failed to find user %s: %w", username, err)
	}

	// Get the group
	groups, err := c.GetGroups(ctx, groupName)
	if err != nil {
		return fmt.Errorf("failed to fetch groups: %w", err)
	}

	var targetGroup *Group
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
	body := map[string]interface{}{
		"groups": append(user.Groups, targetGroup.PK),
	}

	_, err = c.Patch(ctx, "/core/users/"+user.UUID+"/", body)
	if err != nil {
		return fmt.Errorf("failed to add user to group: %w", err)
	}

	return nil
}

// GetEvents retrieves events from Authentik
func (c *Client) GetEvents(ctx context.Context, action string, since time.Time) ([]Event, error) {
	path := "/events/events/"
	if action != "" {
		path += "?action=" + action
	}

	data, err := c.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get events: %w", err)
	}

	var paginatedResp PaginatedResponse[Event]
	if err := json.Unmarshal(data, &paginatedResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Filter events by timestamp
	var filtered []Event
	for _, event := range paginatedResp.Results {
		if event.Timestamp.After(since) {
			filtered = append(filtered, event)
		}
	}

	return filtered, nil
}

// GetRegistrationEvents retrieves user registration events
func (c *Client) GetRegistrationEvents(ctx context.Context, since time.Time) ([]Event, error) {
	return c.GetEvents(ctx, "user_write", since)
}
