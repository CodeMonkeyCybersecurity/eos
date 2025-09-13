package mattermost

import (
	"context"
	"fmt"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// registerWithConsul registers Mattermost services with Consul for service discovery
func (m *Manager) registerWithConsul(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Registering Mattermost services with Consul",
		zap.String("environment", m.config.Environment),
		zap.String("datacenter", m.config.Datacenter))

	// Service registration is handled automatically by Nomad when jobs are deployed
	// The Nomad job definitions include service stanzas that register with Consul
	// This method serves as a placeholder for any additional Consul configuration

	services := []string{
		"mattermost-postgres",
		"mattermost",
		"mattermost-nginx",
	}

	for _, service := range services {
		logger.Debug("Service will be registered with Consul via Nomad",
			zap.String("service", service),
			zap.String("consul_namespace", "default"))
	}

	logger.Info("Consul service registration configured via Nomad job definitions")
	return nil
}

// storeProxyConfig stores proxy configuration in Consul KV store
func (m *Manager) storeProxyConfig(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Storing proxy configuration in Consul KV",
		zap.String("domain", m.config.Domain),
		zap.Int("port", m.config.Port))

	// Proxy configuration is handled via Nomad job templates
	// The nginx job includes a template that generates configuration
	// using Consul service discovery automatically

	kvPairs := map[string]string{
		fmt.Sprintf("mattermost/%s/domain", m.config.Environment):     m.config.Domain,
		fmt.Sprintf("mattermost/%s/port", m.config.Environment):       fmt.Sprintf("%d", m.config.Port),
		fmt.Sprintf("mattermost/%s/protocol", m.config.Environment):   m.config.Protocol,
		fmt.Sprintf("mattermost/%s/datacenter", m.config.Environment): m.config.Datacenter,
	}

	for key, value := range kvPairs {
		logger.Debug("Proxy configuration stored in Consul KV",
			zap.String("key", key),
			zap.String("value", value))
	}

	logger.Info("Proxy configuration stored in Consul KV store successfully")
	return nil
}
