// pkg/consul/sdk/client.go
//
// Consul SDK client utilities and KV helpers.
// Provides centralized SDK access patterns to replace shell command executions.
//
// Last Updated: 2025-01-25

package sdk

import (
	"context"
	"fmt"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewClient creates a new Consul API client with default configuration.
// Uses environment variables for configuration (CONSUL_HTTP_ADDR, CONSUL_HTTP_TOKEN, etc.)
func NewClient() (*consulapi.Client, error) {
	config := consulapi.DefaultConfig()
	client, err := consulapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}
	return client, nil
}

// NewClientWithConfig creates a Consul client with custom configuration.
func NewClientWithConfig(config *consulapi.Config) (*consulapi.Client, error) {
	client, err := consulapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}
	return client, nil
}

// KVPut stores a key-value pair in Consul KV store.
// Replaces: consul kv put <key> <value>
func KVPut(ctx context.Context, client *consulapi.Client, key string, value []byte) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Storing key-value in Consul",
		zap.String("key", key),
		zap.Int("value_size", len(value)))

	kv := client.KV()
	pair := &consulapi.KVPair{
		Key:   key,
		Value: value,
	}

	_, err := kv.Put(pair, nil)
	if err != nil {
		return fmt.Errorf("failed to put key %s: %w", key, err)
	}

	logger.Debug("Key-value stored successfully", zap.String("key", key))
	return nil
}

// KVGet retrieves a value from Consul KV store.
// Replaces: consul kv get <key>
// Returns nil if key does not exist (not an error).
func KVGet(ctx context.Context, client *consulapi.Client, key string) ([]byte, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Retrieving key from Consul", zap.String("key", key))

	kv := client.KV()
	pair, _, err := kv.Get(key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %s: %w", key, err)
	}

	if pair == nil {
		logger.Debug("Key not found", zap.String("key", key))
		return nil, nil
	}

	logger.Debug("Key retrieved successfully",
		zap.String("key", key),
		zap.Int("value_size", len(pair.Value)))

	return pair.Value, nil
}

// KVDelete removes a key from Consul KV store.
// Replaces: consul kv delete <key>
func KVDelete(ctx context.Context, client *consulapi.Client, key string) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Deleting key from Consul", zap.String("key", key))

	kv := client.KV()
	_, err := kv.Delete(key, nil)
	if err != nil {
		return fmt.Errorf("failed to delete key %s: %w", key, err)
	}

	logger.Debug("Key deleted successfully", zap.String("key", key))
	return nil
}

// KVList lists all keys with the given prefix.
// Replaces: consul kv get -keys <prefix>
// Returns empty slice if no keys match (not an error).
func KVList(ctx context.Context, client *consulapi.Client, prefix string) ([]string, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Listing keys with prefix", zap.String("prefix", prefix))

	kv := client.KV()
	keys, _, err := kv.Keys(prefix, "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys with prefix %s: %w", prefix, err)
	}

	if keys == nil {
		keys = []string{}
	}

	logger.Debug("Keys listed successfully",
		zap.String("prefix", prefix),
		zap.Int("count", len(keys)))

	return keys, nil
}

// KVExport exports all key-value pairs with the given prefix.
// Replaces: consul kv export <prefix>
// Returns a map of key -> value.
func KVExport(ctx context.Context, client *consulapi.Client, prefix string) (map[string][]byte, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Exporting KV pairs", zap.String("prefix", prefix))

	kv := client.KV()
	pairs, _, err := kv.List(prefix, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to export prefix %s: %w", prefix, err)
	}

	result := make(map[string][]byte)
	for _, pair := range pairs {
		result[pair.Key] = pair.Value
	}

	logger.Debug("KV pairs exported successfully",
		zap.String("prefix", prefix),
		zap.Int("count", len(result)))

	return result, nil
}

// KVImport imports key-value pairs into Consul.
// Replaces: consul kv import @<file>
func KVImport(ctx context.Context, client *consulapi.Client, data map[string][]byte) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Importing KV pairs", zap.Int("count", len(data)))

	kv := client.KV()
	for key, value := range data {
		pair := &consulapi.KVPair{
			Key:   key,
			Value: value,
		}

		_, err := kv.Put(pair, nil)
		if err != nil {
			return fmt.Errorf("failed to import key %s: %w", key, err)
		}
	}

	logger.Debug("KV pairs imported successfully", zap.Int("count", len(data)))
	return nil
}

// KVDeleteTree removes all keys with the given prefix.
// Replaces: consul kv delete -recurse <prefix>
func KVDeleteTree(ctx context.Context, client *consulapi.Client, prefix string) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Deleting key tree", zap.String("prefix", prefix))

	kv := client.KV()
	_, err := kv.DeleteTree(prefix, nil)
	if err != nil {
		return fmt.Errorf("failed to delete tree %s: %w", prefix, err)
	}

	logger.Debug("Key tree deleted successfully", zap.String("prefix", prefix))
	return nil
}

// ============================================================================
// Cluster Operations - Agent, Members, Catalog, Health
// ============================================================================

// AgentSelf retrieves the local agent's information.
// Replaces: consul info (partial - consul info has more detail but this is SDK equivalent)
func AgentSelf(ctx context.Context, client *consulapi.Client) (map[string]map[string]interface{}, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Retrieving agent information")

	self, err := client.Agent().Self()
	if err != nil {
		return nil, fmt.Errorf("failed to get agent info: %w", err)
	}

	logger.Debug("Agent information retrieved successfully")

	return self, nil
}

// AgentMembers retrieves cluster member information.
// Replaces: consul members [-detailed]
func AgentMembers(ctx context.Context, client *consulapi.Client, wan bool) ([]*consulapi.AgentMember, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Retrieving cluster members", zap.Bool("wan", wan))

	members, err := client.Agent().Members(wan)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster members: %w", err)
	}

	logger.Debug("Cluster members retrieved successfully", zap.Int("count", len(members)))

	return members, nil
}

// OperatorRaftGetConfiguration retrieves the raft peer configuration.
// Replaces: consul operator raft list-peers
func OperatorRaftGetConfiguration(ctx context.Context, client *consulapi.Client) (*consulapi.RaftConfiguration, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Retrieving raft configuration")

	raftConfig, err := client.Operator().RaftGetConfiguration(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get raft configuration: %w", err)
	}

	logger.Debug("Raft configuration retrieved successfully",
		zap.Int("server_count", len(raftConfig.Servers)))

	return raftConfig, nil
}

// CatalogServices lists all services in the catalog.
// Replaces: consul catalog services
func CatalogServices(ctx context.Context, client *consulapi.Client) (map[string][]string, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Listing catalog services")

	services, _, err := client.Catalog().Services(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list catalog services: %w", err)
	}

	logger.Debug("Catalog services listed successfully", zap.Int("count", len(services)))

	return services, nil
}

// HealthService retrieves health information for a specific service.
// Replaces: consul health service <name> [-format=json]
func HealthService(ctx context.Context, client *consulapi.Client, serviceName string, tag string, passingOnly bool) ([]*consulapi.ServiceEntry, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Retrieving service health",
		zap.String("service", serviceName),
		zap.String("tag", tag),
		zap.Bool("passing_only", passingOnly))

	entries, _, err := client.Health().Service(serviceName, tag, passingOnly, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get service health for %s: %w", serviceName, err)
	}

	logger.Debug("Service health retrieved successfully",
		zap.String("service", serviceName),
		zap.Int("entries", len(entries)))

	return entries, nil
}
