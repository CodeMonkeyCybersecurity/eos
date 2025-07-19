package hera

import (
	"context"
	"fmt"
	"time"

	"github.com/Nerzal/gocloak/v13"
)

// Ensure Client (Keycloak) implements AuthClient interface
var _ AuthClient = (*Client)(nil)

func NewClient(url, clientID, clientSecret string, realm string) (*Client, error) {
	ctx := context.Background()
	kc := gocloak.NewClient(url)

	token, err := kc.LoginClient(ctx, clientID, clientSecret, realm)
	if err != nil {
		return nil, fmt.Errorf("keycloak login failed (check client ID/secret/realm): %w", err)
	}

	return &Client{
		client: kc,
		token:  token,
		realm:  realm,
		ctx:    ctx,
	}, nil
}

func (c *Client) GetRegistrationEvents(realm string, since time.Time) ([]gocloak.EventRepresentation, error) {
	events, err := c.client.GetEvents(c.ctx, c.token.AccessToken, realm, gocloak.GetEventsParams{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch events: %w", err)
	}

	filtered := []gocloak.EventRepresentation{}
	for _, evPtr := range events {
		if evPtr.Type != nil && *evPtr.Type == "REGISTER" {
			if evPtr.Time > 0 && time.UnixMilli(evPtr.Time).After(since) {
				filtered = append(filtered, *evPtr)
			}
		}
	}
	return filtered, nil
}

func (c *Client) GroupExistsInRealm(realm, groupName string) (bool, error) {
	groups, err := c.client.GetGroups(c.ctx, c.token.AccessToken, realm, gocloak.GetGroupsParams{Search: &groupName})
	if err != nil {
		return false, fmt.Errorf("failed to fetch groups: %w", err)
	}
	for _, g := range groups {
		if g.Name != nil && *g.Name == groupName {
			return true, nil
		}
	}
	return false, nil
}

// GroupExists implements AuthClient interface for Keycloak client
func (c *Client) GroupExists(groupName string) (bool, error) {
	return c.GroupExistsInRealm(c.realm, groupName)
}

func (c *Client) CreateGroupInRealm(realm, groupName string) error {
	_, err := c.client.CreateGroup(c.ctx, c.token.AccessToken, realm, gocloak.Group{
		Name: &groupName,
	})
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}
	return nil
}

func (c *Client) GetUserID(realm, username string) (string, error) {
	users, err := c.client.GetUsers(c.ctx, c.token.AccessToken, realm, gocloak.GetUsersParams{
		Username: &username,
	})
	if err != nil {
		return "", fmt.Errorf("failed to fetch user: %w", err)
	}
	if len(users) == 0 || users[0].ID == nil {
		return "", fmt.Errorf("user not found: %s", username)
	}
	return *users[0].ID, nil
}

func (c *Client) AssignUserToGroup(realm, userID, groupName string) error {
	groups, err := c.client.GetGroups(c.ctx, c.token.AccessToken, realm, gocloak.GetGroupsParams{Search: &groupName})
	if err != nil {
		return fmt.Errorf("failed to fetch groups for assignment: %w", err)
	}
	if len(groups) == 0 || groups[0].ID == nil {
		return fmt.Errorf("group not found: %s", groupName)
	}
	return c.client.AddUserToGroup(c.ctx, c.token.AccessToken, realm, userID, *groups[0].ID)
}

// CreateGroup implements AuthClient interface for Keycloak client
func (c *Client) CreateGroup(groupName string) error {
	return c.CreateGroupInRealm(c.realm, groupName)
}

// AddUserToGroup implements AuthClient interface for Keycloak client
func (c *Client) AddUserToGroup(username, groupName string) error {
	userID, err := c.GetUserID(c.realm, username)
	if err != nil {
		return err
	}
	return c.AssignUserToGroup(c.realm, userID, groupName)
}
