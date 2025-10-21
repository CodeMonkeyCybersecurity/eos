// Package azure provides Consul KV integration for Azure OpenAI configuration storage
package azure

import (
	"context"
	"fmt"

	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// StoreConfigInConsul stores non-secret Azure OpenAI configuration in Consul KV
// Secrets (API keys) are stored in Vault, not Consul
func StoreConfigInConsul(ctx context.Context, consulClient *api.Client, config *OpenAIConfig) error {
	logger := otelzap.Ctx(ctx)

	if consulClient == nil {
		logger.Warn("Consul client not initialized, skipping Consul KV storage")
		return nil
	}

	// Base path: service/{service-name}/config/azure_openai/
	basePath := fmt.Sprintf("service/%s/config/azure_openai", config.ServiceName)

	logger.Info("Storing Azure OpenAI config in Consul KV", zap.String("base_path", basePath))

	// Store each configuration value
	kv := consulClient.KV()

	// Endpoint (non-secret)
	if _, err := kv.Put(&api.KVPair{
		Key:   basePath + "/endpoint",
		Value: []byte(config.Endpoint),
	}, nil); err != nil {
		return fmt.Errorf("failed to store endpoint in Consul: %w", err)
	}

	// API Version (non-secret)
	if _, err := kv.Put(&api.KVPair{
		Key:   basePath + "/api_version",
		Value: []byte(config.APIVersion),
	}, nil); err != nil {
		return fmt.Errorf("failed to store API version in Consul: %w", err)
	}

	// Chat Deployment (non-secret)
	if _, err := kv.Put(&api.KVPair{
		Key:   basePath + "/chat_deployment",
		Value: []byte(config.ChatDeployment),
	}, nil); err != nil {
		return fmt.Errorf("failed to store chat deployment in Consul: %w", err)
	}

	// Embeddings Deployment (non-secret, optional)
	if config.EmbeddingsDeployment != "" {
		if _, err := kv.Put(&api.KVPair{
			Key:   basePath + "/embeddings_deployment",
			Value: []byte(config.EmbeddingsDeployment),
		}, nil); err != nil {
			return fmt.Errorf("failed to store embeddings deployment in Consul: %w", err)
		}
	}

	// Environment (metadata)
	if config.Environment != "" {
		if _, err := kv.Put(&api.KVPair{
			Key:   basePath + "/environment",
			Value: []byte(config.Environment),
		}, nil); err != nil {
			return fmt.Errorf("failed to store environment in Consul: %w", err)
		}
	}

	logger.Info("Azure OpenAI config stored in Consul KV successfully",
		zap.String("service", config.ServiceName),
		zap.String("endpoint", RedactEndpoint(config.Endpoint)))

	return nil
}

// LoadConfigFromConsul loads Azure OpenAI configuration from Consul KV
func LoadConfigFromConsul(ctx context.Context, consulClient *api.Client, serviceName string) (*OpenAIConfig, error) {
	logger := otelzap.Ctx(ctx)

	if consulClient == nil {
		return nil, fmt.Errorf("consul client not initialized")
	}

	basePath := fmt.Sprintf("service/%s/config/azure_openai", serviceName)
	logger.Info("Loading Azure OpenAI config from Consul KV", zap.String("base_path", basePath))

	kv := consulClient.KV()
	config := &OpenAIConfig{
		ServiceName: serviceName,
	}

	// Load endpoint
	if pair, _, err := kv.Get(basePath+"/endpoint", nil); err != nil {
		return nil, fmt.Errorf("failed to get endpoint from Consul: %w", err)
	} else if pair != nil {
		config.Endpoint = string(pair.Value)
	}

	// Load API version
	if pair, _, err := kv.Get(basePath+"/api_version", nil); err != nil {
		return nil, fmt.Errorf("failed to get API version from Consul: %w", err)
	} else if pair != nil {
		config.APIVersion = string(pair.Value)
	} else {
		config.APIVersion = "2024-02-15-preview" // Default
	}

	// Load chat deployment
	if pair, _, err := kv.Get(basePath+"/chat_deployment", nil); err != nil {
		return nil, fmt.Errorf("failed to get chat deployment from Consul: %w", err)
	} else if pair != nil {
		config.ChatDeployment = string(pair.Value)
	}

	// Load embeddings deployment (optional)
	if pair, _, err := kv.Get(basePath+"/embeddings_deployment", nil); err == nil && pair != nil {
		config.EmbeddingsDeployment = string(pair.Value)
	}

	// Load environment
	if pair, _, err := kv.Get(basePath+"/environment", nil); err == nil && pair != nil {
		config.Environment = string(pair.Value)
	}

	// Validate loaded config
	if config.Endpoint == "" || config.ChatDeployment == "" {
		return nil, fmt.Errorf("incomplete configuration in Consul KV (missing endpoint or chat deployment)")
	}

	logger.Info("Azure OpenAI config loaded from Consul KV successfully",
		zap.String("service", serviceName),
		zap.String("endpoint", RedactEndpoint(config.Endpoint)))

	return config, nil
}

// DeleteConfigFromConsul deletes Azure OpenAI configuration from Consul KV
func DeleteConfigFromConsul(ctx context.Context, consulClient *api.Client, serviceName string) error {
	logger := otelzap.Ctx(ctx)

	if consulClient == nil {
		return fmt.Errorf("consul client not initialized")
	}

	basePath := fmt.Sprintf("service/%s/config/azure_openai", serviceName)
	logger.Info("Deleting Azure OpenAI config from Consul KV", zap.String("base_path", basePath))

	kv := consulClient.KV()

	// Delete entire subtree
	if _, err := kv.DeleteTree(basePath, nil); err != nil {
		return fmt.Errorf("failed to delete Azure OpenAI config from Consul: %w", err)
	}

	logger.Info("Azure OpenAI config deleted from Consul KV successfully", zap.String("service", serviceName))
	return nil
}
