package repository

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"code.gitea.io/sdk/gitea"
)

// GiteaClient wraps the official SDK to provide higher level helpers.
type GiteaClient struct {
	client   *gitea.Client
	username string
}

// NewGiteaClient constructs a client using token authentication.
func NewGiteaClient(cfg *GiteaConfig) (*GiteaClient, error) {
	if cfg == nil {
		return nil, errors.New("gitea configuration is required")
	}

	baseURL := strings.TrimRight(cfg.URL, "/")
	client, err := gitea.NewClient(baseURL, gitea.SetToken(cfg.Token))
	if err != nil {
		return nil, fmt.Errorf("failed to create Gitea client: %w", err)
	}

	return &GiteaClient{
		client:   client,
		username: cfg.Username,
	}, nil
}

// Username returns the configured default repository owner.
func (c *GiteaClient) Username() string {
	return c.username
}

// RepoExists checks whether the repository exists and returns it when found.
func (c *GiteaClient) RepoExists(owner, repo string) (*gitea.Repository, bool, error) {
	r, resp, err := c.client.GetRepo(owner, repo)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to query repository %s/%s: %w", owner, repo, err)
	}
	return r, true, nil
}

// OrgExists checks if the specified organization is present on the server.
func (c *GiteaClient) OrgExists(org string) (bool, error) {
	if strings.TrimSpace(org) == "" {
		return false, nil
	}

	_, resp, err := c.client.GetOrg(org)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to query organization %s: %w", org, err)
	}
	return true, nil
}

// CreateUserRepo creates a repository in the authenticated user's namespace.
func (c *GiteaClient) CreateUserRepo(opts *gitea.CreateRepoOption) (*gitea.Repository, error) {
	repo, resp, err := c.client.CreateRepo(*opts)
	if err != nil {
		return nil, c.wrapError("create user repo", resp, err)
	}
	return repo, nil
}

// CreateOrgRepo creates a repository under an organization.
func (c *GiteaClient) CreateOrgRepo(org string, opts *gitea.CreateRepoOption) (*gitea.Repository, error) {
	repo, resp, err := c.client.CreateOrgRepo(org, *opts)
	if err != nil {
		return nil, c.wrapError("create org repo", resp, err)
	}
	return repo, nil
}

// wrapError converts SDK errors to actionable messages.
func (c *GiteaClient) wrapError(operation string, resp *gitea.Response, err error) error {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return fmt.Errorf("%s failed: authentication denied (check Gitea token)", operation)
		case http.StatusConflict:
			return fmt.Errorf("%s failed: repository already exists", operation)
		case http.StatusUnprocessableEntity:
			return fmt.Errorf("%s failed: invalid request (%s)", operation, err.Error())
		}
	}

	return fmt.Errorf("%s failed: %w", operation, err)
}
