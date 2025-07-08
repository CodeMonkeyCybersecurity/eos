// pkg/hetzner/primary_servers.go

package hetzner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GetZoneIDForDomain fetches all zones from Hetzner and attempts to match the given domain.
func GetZoneIDForDomain(rc *eos_io.RuntimeContext, token, domain string) (string, error) {
	domain = strings.TrimSuffix(domain, ".")

	req, err := http.NewRequest("GET", hetznerAPIBase+"/zones", nil)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to create request for fetching zones", zap.Error(err))
		return "", err
	}
	req.Header.Set("Auth-API-Token", token)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to execute HTTP request for fetching zones", zap.Error(err))
		return "", err
	}
	defer shared.SafeClose(rc.Ctx, resp.Body)

	if resp.StatusCode != http.StatusOK {
		otelzap.Ctx(rc.Ctx).Error("Unexpected status from zones list",
			zap.Int("statusCode", resp.StatusCode),
		)
		return "", fmt.Errorf("unexpected status from zones list: %s", resp.Status)
	}

	var zr ZonesResponse
	if err := json.NewDecoder(resp.Body).Decode(&zr); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to decode JSON for zones response", zap.Error(err))
		return "", err
	}

	for _, z := range zr.Zones {
		zoneName := strings.TrimSuffix(z.Name, ".")
		if zoneName == domain || strings.HasSuffix(domain, zoneName) {
			return z.ID, nil
		}
	}

	err = fmt.Errorf("zone not found for domain %q", domain)
	otelzap.Ctx(rc.Ctx).Error("Zone not found for domain", zap.String("domain", domain), zap.Error(err))
	return "", err
}

// CreateRecord tries to create an A record in Hetzner DNS.
func CreateRecord(rc *eos_io.RuntimeContext, token, zoneID, name, ip string) error {
	reqBody := CreateRecordRequest{
		ZoneID: zoneID,
		Type:   "A",
		Name:   name, // "*" for wildcard or fallback subdomain
		Value:  ip,
		TTL:    300, // Adjust as desired
	}

	bodyBytes, err := json.Marshal(&reqBody)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to marshal CreateRecordRequest", zap.Error(err))
		return err
	}

	req, err := http.NewRequest("POST", hetznerAPIBase+"/records", bytes.NewBuffer(bodyBytes))
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to create request for creating record", zap.Error(err))
		return err
	}
	req.Header.Set("Auth-API-Token", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to execute HTTP request for creating record", zap.Error(err))
		return err
	}
	defer shared.SafeClose(rc.Ctx, resp.Body)

	if resp.StatusCode != http.StatusCreated {
		var responseBody bytes.Buffer
		_, _ = responseBody.ReadFrom(resp.Body)
		errMsg := fmt.Sprintf("record creation failed (%d): %s",
			resp.StatusCode,
			responseBody.String(),
		)
		otelzap.Ctx(rc.Ctx).Error("createRecord: unexpected status", zap.String("error", errMsg))
		return err
	}

	var recordResp RecordResponse
	if err := json.NewDecoder(resp.Body).Decode(&recordResp); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to decode record creation response", zap.Error(err))
		return err
	}

	otelzap.Ctx(rc.Ctx).Debug("Record creation response decoded successfully",
		zap.String("recordID", recordResp.Record.ID),
		zap.String("recordName", recordResp.Record.Name),
		zap.String("recordType", recordResp.Record.Type),
	)
	return nil
}

const hetznerAPIBase = "https://dns.hetzner.com/api/v1"

// CreateRecordRequest is the request body for creating or updating a DNS record.
type CreateRecordRequest struct {
	ZoneID string `json:"zone_id"`
	Type   string `json:"type"` // e.g. "A", "CNAME"
	Name   string `json:"name"`
	Value  string `json:"value"`
	TTL    int    `json:"ttl"`
}

// RecordResponse holds data for the record creation response.
type RecordResponse struct {
	Record struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"record"`
}

// ZonesResponse is used to decode the JSON containing a list of zones.
type ZonesResponse struct {
	Zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"zones"`
}

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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("unexpected status %d", resp.StatusCode)
	}

	var result primaryServerListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding primary server list")
	}

	c.Log.Info(" Retrieved primary servers", zap.Int("count", len(result.PrimaryServers)))
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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("create failed: status %d, body: %s", resp.StatusCode, string(raw))
	}

	var result primaryServerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding create response")
	}

	c.Log.Info(" Created primary server", zap.String("id", result.PrimaryServer.ID))
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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("unexpected status %d", resp.StatusCode)
	}

	var result primaryServerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding response")
	}

	c.Log.Info(" Retrieved primary server", zap.String("id", result.PrimaryServer.ID))
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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("update failed: status %d, body: %s", resp.StatusCode, string(raw))
	}

	var result primaryServerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding response")
	}

	c.Log.Info(" Updated primary server", zap.String("id", result.PrimaryServer.ID))
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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return errors.Errorf("delete failed: status %d, body: %s", resp.StatusCode, string(raw))
	}

	c.Log.Info(" Deleted primary server", zap.String("id", id))
	return nil
}
