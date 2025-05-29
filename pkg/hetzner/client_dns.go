// pkg/hetzner/client.go

package hetzner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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

func (c *DNSClient) doRequest(rc *eos_io.RuntimeContext, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(rc.Ctx, method, baseURL+path, body)
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

func (c *DNSClient) GetServers(rc *eos_io.RuntimeContext) ([]map[string]interface{}, error) {
	resp, err := c.doRequest(rc, "GET", "/servers", nil)
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

func (c *DNSClient) DeleteServer(rc *eos_io.RuntimeContext, id string) error {
	resp, err := c.doRequest(rc, "DELETE", fmt.Sprintf("/servers/%s", id), nil)
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

func (c *DNSClient) CreateServer(rc *eos_io.RuntimeContext, name string, image string, serverType string) (map[string]interface{}, error) {
	payload := fmt.Sprintf(`{"name":"%s","image":"%s","server_type":"%s","location":"nbg1"}`, name, image, serverType)
	resp, err := c.doRequest(rc, "POST", "/servers", strings.NewReader(payload))
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
