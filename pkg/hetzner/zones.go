// pkg/hetzner/zones.go

package hetzner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/cockroachdb/errors"
	"go.uber.org/zap"
)

func (c *DNSClient) GetZones(rc *eos_io.RuntimeContext) ([]DNSZone, error) {
	req, err := http.NewRequestWithContext(rc.Ctx, "GET", zonesBaseURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating GET /zones")
	}
	req.Header.Set("Auth-API-Token", c.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "performing GET /zones")
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

	var result dnsZoneListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding zone list")
	}

	c.Log.Info("✅ Retrieved zones", zap.Int("count", len(result.Zones)))
	return result.Zones, nil
}

func (c *DNSClient) CreateZone(rc *eos_io.RuntimeContext, zone DNSZone) (*DNSZone, error) {
	payload, _ := json.Marshal(zone)

	req, err := http.NewRequestWithContext(rc.Ctx, "POST", zonesBaseURL, bytes.NewReader(payload))
	if err != nil {
		return nil, errors.Wrap(err, "creating POST /zones")
	}
	req.Header.Set("Auth-API-Token", c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "executing POST /zones")
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("create zone failed (%d): %s", resp.StatusCode, raw)
	}

	var result dnsZoneResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding response")
	}

	c.Log.Info("📦 Created zone", zap.String("id", result.Zone.ID))
	return &result.Zone, nil
}

func (c *DNSClient) GetZone(rc *eos_io.RuntimeContext, zoneID string) (*DNSZone, error) {
	url := fmt.Sprintf("%s/%s", zonesBaseURL, zoneID)

	req, err := http.NewRequestWithContext(rc.Ctx, "GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating GET /zones/{id}")
	}
	req.Header.Set("Auth-API-Token", c.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "executing GET /zones/{id}")
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("get zone failed (%d)", resp.StatusCode)
	}

	var result dnsZoneResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding response")
	}

	c.Log.Info("🔍 Retrieved zone", zap.String("id", result.Zone.ID))
	return &result.Zone, nil
}

func (c *DNSClient) UpdateZone(rc *eos_io.RuntimeContext, zoneID string, updated DNSZone) (*DNSZone, error) {
	url := fmt.Sprintf("%s/%s", zonesBaseURL, zoneID)
	payload, _ := json.Marshal(updated)

	req, err := http.NewRequestWithContext(rc.Ctx, "PUT", url, bytes.NewReader(payload))
	if err != nil {
		return nil, errors.Wrap(err, "creating PUT /zones/{id}")
	}
	req.Header.Set("Auth-API-Token", c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "executing PUT /zones/{id}")
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("update failed (%d): %s", resp.StatusCode, raw)
	}

	var result dnsZoneResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding response")
	}

	c.Log.Info("✏️ Updated zone", zap.String("id", result.Zone.ID))
	return &result.Zone, nil
}

func (c *DNSClient) DeleteZone(rc *eos_io.RuntimeContext, zoneID string) error {
	url := fmt.Sprintf("%s/%s", zonesBaseURL, zoneID)

	req, err := http.NewRequestWithContext(rc.Ctx, "DELETE", url, nil)
	if err != nil {
		return errors.Wrap(err, "creating DELETE /zones/{id}")
	}
	req.Header.Set("Auth-API-Token", c.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "executing DELETE /zones/{id}")
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return errors.Errorf("delete failed (%d): %s", resp.StatusCode, raw)
	}

	c.Log.Info("🗑️ Deleted zone", zap.String("id", zoneID))
	return nil
}

func (c *DNSClient) ImportZoneFilePlain(rc *eos_io.RuntimeContext, zoneID string, zoneFile string) error {
	url := fmt.Sprintf("%s/%s/import", zonesBaseURL, zoneID)
	body := strings.NewReader(zoneFile)

	req, err := http.NewRequestWithContext(rc.Ctx, "POST", url, body)
	if err != nil {
		return errors.Wrap(err, "creating POST /zones/{id}/import")
	}
	req.Header.Set("Auth-API-Token", c.Token)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "executing POST /zones/{id}/import")
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return errors.Errorf("import failed (%d): %s", resp.StatusCode, raw)
	}

	c.Log.Info("📥 Imported zone file", zap.String("zone_id", zoneID))
	return nil
}

func (c *DNSClient) ExportZoneFile(rc *eos_io.RuntimeContext, zoneID string) (string, error) {
	url := fmt.Sprintf("%s/%s/export", zonesBaseURL, zoneID)

	req, err := http.NewRequestWithContext(rc.Ctx, "GET", url, nil)
	if err != nil {
		return "", errors.Wrap(err, "creating GET /zones/{id}/export")
	}
	req.Header.Set("Auth-API-Token", c.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "executing GET /zones/{id}/export")
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", errors.Errorf("export failed (%d)", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "reading export data")
	}

	c.Log.Info("📤 Exported zone file", zap.String("zone_id", zoneID))
	return string(data), nil
}

func (c *DNSClient) ValidateZoneFile(rc *eos_io.RuntimeContext, zoneFile string) error {
	url := zonesBaseURL + "/file/validate"
	body := strings.NewReader(zoneFile)

	req, err := http.NewRequestWithContext(rc.Ctx, "POST", url, body)
	if err != nil {
		return errors.Wrap(err, "creating POST /zones/file/validate")
	}
	req.Header.Set("Auth-API-Token", c.Token)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "executing POST /zones/file/validate")
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return errors.Errorf("validate failed (%d): %s", resp.StatusCode, raw)
	}

	c.Log.Info("✅ Validated zone file")
	return nil
}
