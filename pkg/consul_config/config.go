// pkg/consul_config/config.go

package consul_config

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Client wraps Consul API client for config operations
type Client struct {
	consul *api.Client
	prefix string
}

// NewClient creates a new Consul config client
func NewClient(ctx context.Context) (*Client, error) {
	logger := otelzap.Ctx(ctx)

	config := api.DefaultConfig()

	// Try to get Consul address from environment
	if consulAddr := os.Getenv("CONSUL_HTTP_ADDR"); consulAddr != "" {
		config.Address = consulAddr
		logger.Debug("Using CONSUL_HTTP_ADDR from environment", zap.String("addr", consulAddr))
	} else {
		// Default to localhost:8161 (your Consul port from previous conversations)
		config.Address = "localhost:8161"
		logger.Debug("Using default Consul address", zap.String("addr", config.Address))
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Test connectivity
	_, err = client.Status().Leader()
	if err != nil {
		return nil, fmt.Errorf("consul not reachable at %s: %w", config.Address, err)
	}

	return &Client{
		consul: client,
		prefix: "eos/config", // All EOS config stored under this prefix
	}, nil
}

// Get retrieves a configuration value from Consul KV
func (c *Client) Get(ctx context.Context, key string) (string, bool, error) {
	logger := otelzap.Ctx(ctx)
	fullKey := fmt.Sprintf("%s/%s", c.prefix, key)

	kv := c.consul.KV()
	pair, _, err := kv.Get(fullKey, nil)
	if err != nil {
		logger.Warn("Failed to get config from Consul",
			zap.String("key", fullKey),
			zap.Error(err))
		return "", false, err
	}

	if pair == nil {
		logger.Debug("Config key not found in Consul", zap.String("key", fullKey))
		return "", false, nil
	}

	value := string(pair.Value)
	logger.Debug("Retrieved config from Consul",
		zap.String("key", fullKey),
		zap.String("value", value))

	return value, true, nil
}

// Set stores a configuration value in Consul KV
func (c *Client) Set(ctx context.Context, key, value string) error {
	logger := otelzap.Ctx(ctx)
	fullKey := fmt.Sprintf("%s/%s", c.prefix, key)

	kv := c.consul.KV()
	pair := &api.KVPair{
		Key:   fullKey,
		Value: []byte(value),
	}

	_, err := kv.Put(pair, nil)
	if err != nil {
		logger.Error("Failed to store config in Consul",
			zap.String("key", fullKey),
			zap.Error(err))
		return fmt.Errorf("failed to store config: %w", err)
	}

	logger.Info("Stored config in Consul",
		zap.String("key", fullKey),
		zap.String("value", value))

	return nil
}

// Delete removes a configuration value from Consul KV
func (c *Client) Delete(ctx context.Context, key string) error {
	logger := otelzap.Ctx(ctx)
	fullKey := fmt.Sprintf("%s/%s", c.prefix, key)

	kv := c.consul.KV()
	_, err := kv.Delete(fullKey, nil)
	if err != nil {
		logger.Error("Failed to delete config from Consul",
			zap.String("key", fullKey),
			zap.Error(err))
		return fmt.Errorf("failed to delete config: %w", err)
	}

	logger.Info("Deleted config from Consul", zap.String("key", fullKey))
	return nil
}

// List returns all config keys under a prefix
func (c *Client) List(ctx context.Context, subPrefix string) (map[string]string, error) {
	logger := otelzap.Ctx(ctx)
	fullPrefix := fmt.Sprintf("%s/%s", c.prefix, subPrefix)

	kv := c.consul.KV()
	pairs, _, err := kv.List(fullPrefix, nil)
	if err != nil {
		logger.Warn("Failed to list configs from Consul",
			zap.String("prefix", fullPrefix),
			zap.Error(err))
		return nil, err
	}

	result := make(map[string]string)
	for _, pair := range pairs {
		// Remove the full prefix to get just the key name
		key := strings.TrimPrefix(pair.Key, fullPrefix+"/")
		if key != "" { // Skip the prefix itself if it's a key
			result[key] = string(pair.Value)
		}
	}

	logger.Debug("Listed configs from Consul",
		zap.String("prefix", fullPrefix),
		zap.Int("count", len(result)))

	return result, nil
}

// GetWithFallback tries to get config from Consul, falls back to provided value
func (c *Client) GetWithFallback(ctx context.Context, key, fallback string) string {
	value, found, err := c.Get(ctx, key)
	if err != nil || !found {
		return fallback
	}
	return value
}

// IsAvailable checks if Consul is reachable
func IsAvailable(ctx context.Context) bool {
	_, err := NewClient(ctx)
	return err == nil
}
