// pkg/hetzner/records.go

package hetzner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/cockroachdb/errors"
	"go.uber.org/zap"
)

func (c *HetznerClient) GetRecords(ctx context.Context, zoneID string) ([]DNSRecord, error) {
	url := fmt.Sprintf("%s?zone_id=%s", recordsBaseURL, zoneID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating GET request for records")
	}
	req.Header.Set("Auth-API-Token", c.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "performing GET /records")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result dnsRecordListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding response")
	}

	c.Log.Info("✅ Retrieved records", zap.Int("count", len(result.Records)))
	return result.Records, nil
}

func (c *HetznerClient) CreateRecord(ctx context.Context, record DNSRecord) (*DNSRecord, error) {
	payload, _ := json.Marshal(record)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, recordsBaseURL, bytes.NewReader(payload))
	if err != nil {
		return nil, errors.Wrap(err, "creating POST request")
	}
	req.Header.Set("Auth-API-Token", c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "performing POST /records")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("create failed (%d): %s", resp.StatusCode, raw)
	}

	var result dnsRecordResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding response")
	}

	c.Log.Info("📦 Created record", zap.String("id", result.Record.ID))
	return &result.Record, nil
}

func (c *HetznerClient) GetRecord(ctx context.Context, id string) (*DNSRecord, error) {
	url := fmt.Sprintf("%s/%s", recordsBaseURL, id)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating GET /records/{id}")
	}
	req.Header.Set("Auth-API-Token", c.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "executing GET /records/{id}")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("get record failed: status %d", resp.StatusCode)
	}

	var result dnsRecordResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding response")
	}

	c.Log.Info("🔍 Fetched record", zap.String("id", result.Record.ID))
	return &result.Record, nil
}

func (c *HetznerClient) UpdateRecord(ctx context.Context, id string, updated DNSRecord) (*DNSRecord, error) {
	url := fmt.Sprintf("%s/%s", recordsBaseURL, id)
	payload, _ := json.Marshal(updated)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(payload))
	if err != nil {
		return nil, errors.Wrap(err, "creating PUT request")
	}
	req.Header.Set("Auth-API-Token", c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "executing PUT /records/{id}")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("update failed (%d): %s", resp.StatusCode, raw)
	}

	var result dnsRecordResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding response")
	}

	c.Log.Info("✏️ Updated record", zap.String("id", result.Record.ID))
	return &result.Record, nil
}

func (c *HetznerClient) DeleteRecord(ctx context.Context, id string) error {
	url := fmt.Sprintf("%s/%s", recordsBaseURL, id)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return errors.Wrap(err, "creating DELETE request")
	}
	req.Header.Set("Auth-API-Token", c.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "executing DELETE /records/{id}")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return errors.Errorf("delete failed (%d): %s", resp.StatusCode, raw)
	}

	c.Log.Info("🗑️ Deleted record", zap.String("id", id))
	return nil
}

func (c *HetznerClient) BulkCreateRecords(ctx context.Context, records []DNSRecord) error {
	return c.bulkSend(ctx, "POST", records)
}

func (c *HetznerClient) BulkUpdateRecords(ctx context.Context, records []DNSRecord) error {
	return c.bulkSend(ctx, "PUT", records)
}

func (c *HetznerClient) bulkSend(ctx context.Context, method string, records []DNSRecord) error {
	payload, _ := json.Marshal(bulkRecordsPayload{Records: records})

	req, err := http.NewRequestWithContext(ctx, method, recordsBaseURL+"/bulk", bytes.NewReader(payload))
	if err != nil {
		return errors.Wrap(err, "creating bulk request")
	}
	req.Header.Set("Auth-API-Token", c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "performing bulk request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		return errors.Errorf("bulk %s failed (%d): %s", method, resp.StatusCode, raw)
	}

	c.Log.Info("📦 Bulk records operation complete", zap.String("method", method), zap.Int("count", len(records)))
	return nil
}
