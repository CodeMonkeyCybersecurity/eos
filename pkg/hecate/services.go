// Package hecate provides the reverse proxy framework for Eos
package hecate

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
)

// ServiceCatalog defines all available services that can be deployed with Hecate
var ServiceCatalog = map[string]terraform.ServiceDefinition{
	"wazuh": {
		Name:         "wazuh",
		DisplayName:  "Wazuh SIEM",
		Description:  "Open source security platform for threat detection and response",
		Category:     terraform.CategorySecurity,
		NomadJobPath: "assets/nomad/wazuh.nomad",
		Dependencies: []string{"elasticsearch"},
		Ports: []terraform.ServicePort{
			{Name: "api", Port: 55000, Protocol: "tcp", Public: true},
			{Name: "registration", Port: 1514, Protocol: "tcp", Public: false},
			{Name: "agent", Port: 1515, Protocol: "tcp", Public: false},
		},
		AuthPolicy:     "security-admins",
		HealthEndpoint: "/api/health",
		Subdomain:      "wazuh",
		Resources: terraform.ResourceRequirements{
			CPU:    "2000",
			Memory: "4096",
			Disk:   "20GB",
		},
		Configuration: map[string]any{
			"cluster_name": "wazuh-cluster",
			"node_type":    "master",
		},
	},
	"grafana": {
		Name:         "grafana",
		DisplayName:  "Grafana",
		Description:  "Open source analytics and monitoring solution",
		Category:     terraform.CategoryMonitoring,
		NomadJobPath: "assets/nomad/grafana.nomad",
		Dependencies: []string{"prometheus", "loki"},
		Ports: []terraform.ServicePort{
			{Name: "http", Port: 3000, Protocol: "tcp", Public: true},
		},
		AuthPolicy:     "monitoring-users",
		HealthEndpoint: "/api/health",
		Subdomain:      "grafana",
		Resources: terraform.ResourceRequirements{
			CPU:    "500",
			Memory: "512",
			Disk:   "1GB",
		},
		Configuration: map[string]any{
			"admin_user":   "admin",
			"allow_signup": false,
			"auth_proxy":   true,
			"auth_header":  "X-Auth-User",
		},
	},
	"prometheus": {
		Name:         "prometheus",
		DisplayName:  "Prometheus",
		Description:  "Systems monitoring and alerting toolkit",
		Category:     terraform.CategoryMonitoring,
		NomadJobPath: "assets/nomad/prometheus.nomad",
		Dependencies: []string{},
		Ports: []terraform.ServicePort{
			{Name: "http", Port: 9090, Protocol: "tcp", Public: true},
		},
		AuthPolicy:     "monitoring-users",
		HealthEndpoint: "/-/healthy",
		Subdomain:      "prometheus",
		Resources: terraform.ResourceRequirements{
			CPU:    "1000",
			Memory: "2048",
			Disk:   "10GB",
		},
		Configuration: map[string]any{
			"retention_time":  "15d",
			"scrape_interval": "15s",
		},
	},
	"loki": {
		Name:         "loki",
		DisplayName:  "Loki",
		Description:  "Log aggregation system designed to store and query logs",
		Category:     terraform.CategoryMonitoring,
		NomadJobPath: "assets/nomad/loki.nomad",
		Dependencies: []string{},
		Ports: []terraform.ServicePort{
			{Name: "http", Port: 3100, Protocol: "tcp", Public: true},
			{Name: "grpc", Port: 9095, Protocol: "tcp", Public: false},
		},
		AuthPolicy:     "monitoring-users",
		HealthEndpoint: "/ready",
		Subdomain:      "loki",
		Resources: terraform.ResourceRequirements{
			CPU:    "500",
			Memory: "1024",
			Disk:   "10GB",
		},
		Configuration: map[string]any{
			"retention_period":  "744h", // 31 days
			"ingestion_rate_mb": 10,
		},
	},
	"elasticsearch": {
		Name:         "elasticsearch",
		DisplayName:  "Elasticsearch",
		Description:  "Distributed search and analytics engine",
		Category:     terraform.CategoryDatabase,
		NomadJobPath: "assets/nomad/elasticsearch.nomad",
		Dependencies: []string{},
		Ports: []terraform.ServicePort{
			{Name: "http", Port: 9200, Protocol: "tcp", Public: true},
			{Name: "transport", Port: 9300, Protocol: "tcp", Public: false},
		},
		AuthPolicy:     "data-users",
		HealthEndpoint: "/_cluster/health",
		Subdomain:      "elastic",
		Resources: terraform.ResourceRequirements{
			CPU:    "2000",
			Memory: "4096",
			Disk:   "50GB",
		},
		Configuration: map[string]any{
			"cluster_name": "eos-cluster",
			"node_name":    "es-node-1",
			"heap_size":    "2g",
		},
	},
	"kibana": {
		Name:         "kibana",
		DisplayName:  "Kibana",
		Description:  "Data visualization dashboard for Elasticsearch",
		Category:     terraform.CategoryMonitoring,
		NomadJobPath: "assets/nomad/kibana.nomad",
		Dependencies: []string{"elasticsearch"},
		Ports: []terraform.ServicePort{
			{Name: "http", Port: 5601, Protocol: "tcp", Public: true},
		},
		AuthPolicy:     "data-users",
		HealthEndpoint: "/api/status",
		Subdomain:      "kibana",
		Resources: terraform.ResourceRequirements{
			CPU:    "1000",
			Memory: "2048",
			Disk:   "1GB",
		},
		Configuration: map[string]any{
			"elasticsearch_url": "http://elasticsearch.service.consul:9200",
			"server_name":       "kibana.eos.local",
		},
	},
	"mattermost": {
		Name:         "mattermost",
		DisplayName:  "Mattermost",
		Description:  "Open source collaboration platform",
		Category:     terraform.CategoryMessaging,
		NomadJobPath: "assets/nomad/mattermost.nomad",
		Dependencies: []string{"postgres"},
		Ports: []terraform.ServicePort{
			{Name: "http", Port: 8065, Protocol: "tcp", Public: true},
		},
		AuthPolicy:     "all-users",
		HealthEndpoint: "/api/v4/system/ping",
		Subdomain:      "chat",
		Resources: terraform.ResourceRequirements{
			CPU:    "1000",
			Memory: "2048",
			Disk:   "10GB",
		},
		Configuration: map[string]any{
			"site_url":      "https://chat.eos.local",
			"enable_signup": false,
			"enable_oauth":  true,
		},
	},
	"postgres": {
		Name:         "postgres",
		DisplayName:  "PostgreSQL",
		Description:  "Advanced open source relational database",
		Category:     terraform.CategoryDatabase,
		NomadJobPath: "assets/nomad/postgres.nomad",
		Dependencies: []string{},
		Ports: []terraform.ServicePort{
			{Name: "postgres", Port: 5432, Protocol: "tcp", Public: false},
		},
		AuthPolicy:     "database-admins",
		HealthEndpoint: "", // No HTTP health endpoint
		Subdomain:      "", // No web interface
		Resources: terraform.ResourceRequirements{
			CPU:    "1000",
			Memory: "2048",
			Disk:   "20GB",
		},
		Configuration: map[string]any{
			"max_connections": 100,
			"shared_buffers":  "256MB",
			"version":         "15",
		},
	},
	"redis": {
		Name:         "redis",
		DisplayName:  "Redis",
		Description:  "In-memory data structure store",
		Category:     terraform.CategoryDatabase,
		NomadJobPath: "assets/nomad/redis.nomad",
		Dependencies: []string{},
		Ports: []terraform.ServicePort{
			{Name: "redis", Port: 6379, Protocol: "tcp", Public: false},
		},
		AuthPolicy:     "cache-users",
		HealthEndpoint: "", // No HTTP health endpoint
		Subdomain:      "", // No web interface
		Resources: terraform.ResourceRequirements{
			CPU:    "500",
			Memory: "512",
			Disk:   "1GB",
		},
		Configuration: map[string]any{
			"maxmemory":        "256mb",
			"maxmemory_policy": "allkeys-lru",
			"persistence":      "yes",
		},
	},
	"vault": {
		Name:         "vault",
		DisplayName:  "HashiCorp Vault",
		Description:  "Secrets management and data protection",
		Category:     terraform.CategorySecurity,
		NomadJobPath: "assets/nomad/vault.nomad",
		Dependencies: []string{},
		Ports: []terraform.ServicePort{
			{Name: "http", Port: 8200, Protocol: "tcp", Public: true},
			{Name: "cluster", Port: 8201, Protocol: "tcp", Public: false},
		},
		AuthPolicy:     "vault-admins",
		HealthEndpoint: "/v1/sys/health",
		Subdomain:      "vault",
		Resources: terraform.ResourceRequirements{
			CPU:    "500",
			Memory: "512",
			Disk:   "10GB",
		},
		Configuration: map[string]any{
			"storage_backend": "consul",
			"cluster_name":    "eos-vault",
			"ui":              true,
		},
	},
	"consul": {
		Name:         "consul",
		DisplayName:  "HashiCorp Consul",
		Description:  "Service mesh and service discovery",
		Category:     terraform.CategoryDatabase,
		NomadJobPath: "assets/nomad/consul.nomad",
		Dependencies: []string{},
		Ports: []terraform.ServicePort{
			{Name: "http", Port: 8500, Protocol: "tcp", Public: true},
			{Name: "dns", Port: 8600, Protocol: "udp", Public: false},
			{Name: "serf-lan", Port: 8301, Protocol: "tcp", Public: false},
			{Name: "serf-wan", Port: 8302, Protocol: "tcp", Public: false},
			{Name: "server", Port: 8300, Protocol: "tcp", Public: false},
		},
		AuthPolicy:     "consul-admins",
		HealthEndpoint: "/v1/status/leader",
		Subdomain:      "consul",
		Resources: terraform.ResourceRequirements{
			CPU:    "500",
			Memory: "512",
			Disk:   "10GB",
		},
		Configuration: map[string]any{
			"datacenter":       "dc1",
			"bootstrap_expect": 3,
			"ui":               true,
		},
	},
}

// GetService returns a service definition by name
func GetService(name string) (terraform.ServiceDefinition, bool) {
	service, exists := ServiceCatalog[name]
	return service, exists
}

// GetServicesByCategory returns all services in a given category
func GetServicesByCategory(category string) []terraform.ServiceDefinition {
	var services []terraform.ServiceDefinition
	for _, service := range ServiceCatalog {
		if service.Category == category {
			services = append(services, service)
		}
	}
	return services
}

// GetServiceDependencies recursively gets all dependencies for a service
func GetServiceDependencies(serviceName string) []string {
	visited := make(map[string]bool)
	var deps []string

	var collectDeps func(string)
	collectDeps = func(name string) {
		if visited[name] {
			return
		}
		visited[name] = true

		if service, exists := ServiceCatalog[name]; exists {
			for _, dep := range service.Dependencies {
				if !visited[dep] {
					collectDeps(dep)
					deps = append(deps, dep)
				}
			}
		}
	}

	collectDeps(serviceName)
	return deps
}

// ValidateServiceCombination checks if a set of services can be deployed together
func ValidateServiceCombination(services []string) error {
	// Check for circular dependencies
	for _, service := range services {
		deps := GetServiceDependencies(service)
		for _, dep := range deps {
			if !contains(services, dep) {
				// Dependency not in deployment list
				// This is okay - we'll deploy it automatically
			}
		}
	}

	// TODO: Add more validation rules
	// - Check for port conflicts
	// - Check for resource constraints
	// - Check for incompatible services

	return nil
}

// contains checks if a string is in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
