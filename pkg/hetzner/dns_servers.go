// pkg/hetzner/primary_servers.go

package hetzner

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/cockroachdb/errors"
	"go.uber.org/zap"
)

func (c *DNSClient) GetAllPrimaryServers(rc *eos_io.RuntimeContext, zoneID string) ([]PrimaryServer, error) {
	url := hetznerDNSBaseURL + "/primary_servers"
	if zoneID != "" {
		url += "?zone_id=" + zoneID
	}

	req, err := http.NewRequestWithContext(rc.Ctx, "GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating request for primary servers")
	}
	req.Header.Set("Auth-API-Token", c.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "performing GET /primary_servers")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("unexpected status %d", resp.StatusCode)
	}

	var result primaryServerListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding primary server list")
	}

	c.Log.Info("✅ Retrieved primary servers", zap.Int("count", len(result.PrimaryServers)))
	return result.PrimaryServers, nil
}

func (c *DNSClient) CreatePrimaryServer(rc *eos_io.RuntimeContext, zoneID, address string, port int) (*PrimaryServer, error) {
	payload := map[string]interface{}{
		"zone_id": zoneID,
		"address": address,
		"port":    port,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(rc.Ctx, "POST", hetznerDNSBaseURL+"/primary_servers", bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrap(err, "creating request to create primary server")
	}
	req.Header.Set("Auth-API-Token", c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "performing POST /primary_servers")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("create failed: status %d, body: %s", resp.StatusCode, string(raw))
	}

	var result primaryServerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding create response")
	}

	c.Log.Info("✅ Created primary server", zap.String("id", result.PrimaryServer.ID))
	return &result.PrimaryServer, nil
}

func (c *DNSClient) GetPrimaryServer(rc *eos_io.RuntimeContext, id string) (*PrimaryServer, error) {
	url := hetznerDNSBaseURL + "/primary_servers/" + id

	req, err := http.NewRequestWithContext(rc.Ctx, "GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating GET request for primary server")
	}
	req.Header.Set("Auth-API-Token", c.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "performing GET /primary_servers/{id}")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("unexpected status %d", resp.StatusCode)
	}

	var result primaryServerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding response")
	}

	c.Log.Info("📄 Retrieved primary server", zap.String("id", result.PrimaryServer.ID))
	return &result.PrimaryServer, nil
}

func (c *DNSClient) UpdatePrimaryServer(rc *eos_io.RuntimeContext, id, zoneID, address string, port int) (*PrimaryServer, error) {
	payload := map[string]interface{}{
		"zone_id": zoneID,
		"address": address,
		"port":    port,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(rc.Ctx, "PUT", hetznerDNSBaseURL+"/primary_servers/"+id, bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrap(err, "creating PUT request")
	}
	req.Header.Set("Auth-API-Token", c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "performing PUT /primary_servers/{id}")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("update failed: status %d, body: %s", resp.StatusCode, string(raw))
	}

	var result primaryServerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding response")
	}

	c.Log.Info("✏️ Updated primary server", zap.String("id", result.PrimaryServer.ID))
	return &result.PrimaryServer, nil
}

func (c *DNSClient) DeletePrimaryServer(rc *eos_io.RuntimeContext, id string) error {
	req, err := http.NewRequestWithContext(rc.Ctx, "DELETE", hetznerDNSBaseURL+"/primary_servers/"+id, nil)
	if err != nil {
		return errors.Wrap(err, "creating DELETE request")
	}
	req.Header.Set("Auth-API-Token", c.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "performing DELETE /primary_servers/{id}")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return errors.Errorf("delete failed: status %d, body: %s", resp.StatusCode, string(raw))
	}

	c.Log.Info("🗑️ Deleted primary server", zap.String("id", id))
	return nil
}
