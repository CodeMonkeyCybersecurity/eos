// pkg/hetzner/client.go

package hetzner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cockroachdb/errors"
	"go.uber.org/zap"
)

const baseURL = "https://api.hetzner.cloud/v1"

type DNSClient struct {
	Token string
	Log   *zap.Logger
}

func NewClient(token string, log *zap.Logger) *DNSClient {
	return &DNSClient{
		Token: token,
		Log:   log.Named("hetzner"),
	}
}

func (c *DNSClient) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, body)
	if err != nil {
		return nil, errors.Wrap(err, "creating Hetzner API request")
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	c.Log.Debug("🌐 Sending Hetzner API request", zap.String("method", method), zap.String("path", path))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "executing Hetzner API request")
	}
	return resp, nil
}

func (c *DNSClient) GetServers(ctx context.Context) ([]map[string]interface{}, error) {
	resp, err := c.doRequest(ctx, "GET", "/servers", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("unexpected status %d from Hetzner API", resp.StatusCode)
	}

	var result struct {
		Servers []map[string]interface{} `json:"servers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding Hetzner server list")
	}

	c.Log.Info("✅ Retrieved Hetzner servers", zap.Int("count", len(result.Servers)))
	return result.Servers, nil
}

func (c *DNSClient) DeleteServer(ctx context.Context, id string) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/servers/%s", id), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return errors.Errorf("failed to delete server %s, status %d", id, resp.StatusCode)
	}

	c.Log.Info("🗑️ Deleted Hetzner server", zap.String("server_id", id))
	return nil
}

func (c *DNSClient) CreateServer(ctx context.Context, name string, image string, serverType string) (map[string]interface{}, error) {
	payload := fmt.Sprintf(`{"name":"%s","image":"%s","server_type":"%s","location":"nbg1"}`, name, image, serverType)
	resp, err := c.doRequest(ctx, "POST", "/servers", strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, errors.Errorf("failed to create server, status %d", resp.StatusCode)
	}

	var result struct {
		Server map[string]interface{} `json:"server"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding create server response")
	}

	c.Log.Info("🚀 Created Hetzner server", zap.String("name", name))
	return result.Server, nil
}
