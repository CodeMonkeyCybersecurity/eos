package hecate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// StreamManager handles TCP/UDP stream proxy configuration
type StreamManager struct {
	client *HecateClient
}

// NewStreamManager creates a new stream manager
func NewStreamManager(client *HecateClient) *StreamManager {
	return &StreamManager{client: client}
}

// CreateStreamRequest represents a request to create a new stream
type CreateStreamRequest struct {
	Name      string   `json:"name"`
	Protocol  string   `json:"protocol"` // tcp, udp
	Listen    string   `json:"listen"`   // port or host:port
	Upstreams []string `json:"upstreams"`
}

// UpdateStreamRequest represents a request to update a stream
type UpdateStreamRequest struct {
	Upstreams []string `json:"upstreams,omitempty"`
}

// StreamInfo represents stream information
type StreamInfo struct {
	Name      string    `json:"name"`
	Protocol  string    `json:"protocol"`
	Listen    string    `json:"listen"`
	Upstreams []string  `json:"upstreams"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Status    string    `json:"status"`
}

// StreamPreset represents a preset stream configuration
type StreamPreset struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// CreateStream creates a new stream proxy
func (sm *StreamManager) CreateStream(ctx context.Context, req *CreateStreamRequest) (*StreamInfo, error) {
	logger := otelzap.Ctx(sm.client.rc.Ctx)
	logger.Info("Creating stream proxy",
		zap.String("name", req.Name),
		zap.String("protocol", req.Protocol),
		zap.String("listen", req.Listen))

	// Validate request
	if err := sm.validateCreateRequest(req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	stream := &StreamInfo{
		Name:      req.Name,
		Protocol:  req.Protocol,
		Listen:    req.Listen,
		Upstreams: req.Upstreams,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Status:    "creating",
	}

	// Generate Nginx configuration
	nginxConfig := sm.generateNginxConfig(stream)

	// Apply via 
	if err := sm.applyState(ctx, stream, nginxConfig); err != nil {
		return nil, fmt.Errorf("failed to apply stream configuration: %w", err)
	}

	// Store in Consul
	if err := sm.storeStream(ctx, stream); err != nil {
		logger.Warn("Failed to store stream in Consul",
			zap.String("name", req.Name),
			zap.Error(err))
	}

	// Update status
	stream.Status = "active"
	sm.storeStream(ctx, stream)

	logger.Info("Stream proxy created successfully",
		zap.String("name", stream.Name),
		zap.String("protocol", stream.Protocol))

	return stream, nil
}

// CreatePresetStream creates streams from a preset
func (sm *StreamManager) CreatePresetStream(ctx context.Context, preset, upstream string) error {
	logger := otelzap.Ctx(sm.client.rc.Ctx)
	logger.Info("Creating preset streams",
		zap.String("preset", preset),
		zap.String("upstream", upstream))

	presets := map[string][]StreamPreset{
		"mailcow": {
			{Name: "smtp", Port: 25, Protocol: "tcp"},
			{Name: "smtp-tls", Port: 465, Protocol: "tcp"},
			{Name: "submission", Port: 587, Protocol: "tcp"},
			{Name: "imap", Port: 143, Protocol: "tcp"},
			{Name: "imaps", Port: 993, Protocol: "tcp"},
			{Name: "pop3", Port: 110, Protocol: "tcp"},
			{Name: "pop3s", Port: 995, Protocol: "tcp"},
		},
		"jenkins": {
			{Name: "agent", Port: 50000, Protocol: "tcp"},
		},
		"wazuh": {
			{Name: "agent-tcp", Port: 1514, Protocol: "tcp"},
			{Name: "agent-udp", Port: 1514, Protocol: "udp"},
			{Name: "syslog", Port: 1515, Protocol: "tcp"},
		},
		"postgresql": {
			{Name: "postgres", Port: 5432, Protocol: "tcp"},
		},
		"mysql": {
			{Name: "mysql", Port: 3306, Protocol: "tcp"},
		},
		"redis": {
			{Name: "redis", Port: 6379, Protocol: "tcp"},
		},
		"minecraft": {
			{Name: "minecraft", Port: 25565, Protocol: "tcp"},
		},
		"teamspeak": {
			{Name: "ts-voice", Port: 9987, Protocol: "udp"},
			{Name: "ts-query", Port: 10011, Protocol: "tcp"},
			{Name: "ts-transfer", Port: 30033, Protocol: "tcp"},
		},
	}

	presetConfigs, ok := presets[preset]
	if !ok {
		return fmt.Errorf("unknown preset: %s. Available presets: %s", 
			preset, strings.Join(sm.getAvailablePresets(), ", "))
	}

	results := []string{}
	errors := []string{}

	for _, pc := range presetConfigs {
		req := &CreateStreamRequest{
			Name:      fmt.Sprintf("%s-%s", preset, pc.Name),
			Protocol:  pc.Protocol,
			Listen:    fmt.Sprintf(":%d", pc.Port),
			Upstreams: []string{fmt.Sprintf("%s:%d", upstream, pc.Port)},
		}

		if _, err := sm.CreateStream(ctx, req); err != nil {
			errorMsg := fmt.Sprintf("failed to create %s stream: %v", pc.Name, err)
			logger.Error(errorMsg,
				zap.String("preset", preset),
				zap.String("stream", pc.Name),
				zap.Error(err))
			errors = append(errors, errorMsg)
		} else {
			results = append(results, req.Name)
		}
	}

	logger.Info("Preset stream creation completed",
		zap.String("preset", preset),
		zap.Strings("created", results),
		zap.Strings("errors", errors))

	if len(errors) > 0 {
		return fmt.Errorf("some streams failed: %s", strings.Join(errors, "; "))
	}

	return nil
}

// UpdateStream updates an existing stream
func (sm *StreamManager) UpdateStream(ctx context.Context, name string, updates *UpdateStreamRequest) (*StreamInfo, error) {
	logger := otelzap.Ctx(sm.client.rc.Ctx)
	logger.Info("Updating stream",
		zap.String("name", name))

	// Get current stream
	stream, err := sm.GetStream(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get stream: %w", err)
	}

	// Apply updates
	if updates.Upstreams != nil {
		stream.Upstreams = updates.Upstreams
	}
	stream.UpdatedAt = time.Now()

	// Generate new Nginx configuration
	nginxConfig := sm.generateNginxConfig(stream)

	// Apply via 
	if err := sm.applyState(ctx, stream, nginxConfig); err != nil {
		return nil, fmt.Errorf("failed to update stream configuration: %w", err)
	}

	// Update in Consul
	if err := sm.storeStream(ctx, stream); err != nil {
		logger.Warn("Failed to update stream in Consul",
			zap.String("name", name),
			zap.Error(err))
	}

	logger.Info("Stream updated successfully",
		zap.String("name", stream.Name))

	return stream, nil
}

// DeleteStream deletes a stream
func (sm *StreamManager) DeleteStream(ctx context.Context, name string) error {
	logger := otelzap.Ctx(sm.client.rc.Ctx)
	logger.Info("Deleting stream",
		zap.String("name", name))

	// Get stream to check if it exists
	_, err := sm.GetStream(ctx, name)
	if err != nil {
		return fmt.Errorf("stream not found: %w", err)
	}

	// Remove Nginx configuration via 
	if err := sm.removeState(ctx, name); err != nil {
		return fmt.Errorf("failed to remove stream configuration: %w", err)
	}

	// Remove from Consul
	if err := sm.deleteStreamFromConsul(ctx, name); err != nil {
		logger.Warn("Failed to delete stream from Consul",
			zap.String("name", name),
			zap.Error(err))
	}

	logger.Info("Stream deleted successfully",
		zap.String("name", name))

	return nil
}

// GetStream retrieves a stream by name
func (sm *StreamManager) GetStream(ctx context.Context, name string) (*StreamInfo, error) {
	logger := otelzap.Ctx(sm.client.rc.Ctx)
	logger.Debug("Getting stream",
		zap.String("name", name))

	// Get from Consul
	data, _, err := sm.client.consul.KV().Get(fmt.Sprintf("hecate/streams/%s", name), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get stream from Consul: %w", err)
	}

	if data == nil {
		return nil, fmt.Errorf("stream not found")
	}

	var stream StreamInfo
	if err := json.Unmarshal(data.Value, &stream); err != nil {
		return nil, fmt.Errorf("failed to unmarshal stream: %w", err)
	}

	return &stream, nil
}

// ListStreams lists all streams
func (sm *StreamManager) ListStreams(ctx context.Context) ([]*StreamInfo, error) {
	logger := otelzap.Ctx(sm.client.rc.Ctx)
	logger.Debug("Listing streams")

	keys, _, err := sm.client.consul.KV().Keys("hecate/streams/", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list streams: %w", err)
	}

	streams := make([]*StreamInfo, 0, len(keys))
	for _, key := range keys {
		name := strings.TrimPrefix(key, "hecate/streams/")
		if name == "" {
			continue
		}

		stream, err := sm.GetStream(ctx, name)
		if err != nil {
			logger.Warn("Failed to get stream",
				zap.String("name", name),
				zap.Error(err))
			continue
		}

		streams = append(streams, stream)
	}

	logger.Debug("Listed streams",
		zap.Int("count", len(streams)))

	return streams, nil
}

// GetAvailablePresets returns available stream presets
func (sm *StreamManager) GetAvailablePresets() []string {
	return sm.getAvailablePresets()
}

// Helper methods

func (sm *StreamManager) validateCreateRequest(req *CreateStreamRequest) error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}
	if req.Protocol != "tcp" && req.Protocol != "udp" {
		return fmt.Errorf("protocol must be tcp or udp")
	}
	if req.Listen == "" {
		return fmt.Errorf("listen address is required")
	}
	if len(req.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}
	return nil
}

func (sm *StreamManager) generateNginxConfig(stream *StreamInfo) string {
	upstreamList := ""
	for _, upstream := range stream.Upstreams {
		upstreamList += fmt.Sprintf("    server %s;\n", upstream)
	}

	return fmt.Sprintf(`
# Upstream configuration for %s
upstream %s_backend {
%s}

# Stream server configuration
server {
    listen %s %s;
    proxy_pass %s_backend;
    proxy_timeout 1s;
    proxy_connect_timeout 1s;
    proxy_responses 1;
    error_log /var/log/nginx/%s_error.log;
}
`, stream.Name, stream.Name, upstreamList, stream.Listen, stream.Protocol, stream.Name, stream.Name)
}

func (sm *StreamManager) applyState(ctx context.Context, stream *StreamInfo, config string) error {
	state := map[string]interface{}{
		"nginx_stream": map[string]interface{}{
			"name":     stream.Name,
			"config":   config,
			"protocol": stream.Protocol,
			"listen":   stream.Listen,
		},
	}

	return sm.storeStreamConfigInConsul(ctx, "hecate.nginx_stream", state)
}

func (sm *StreamManager) removeState(ctx context.Context, name string) error {
	state := map[string]interface{}{
		"nginx_stream_remove": map[string]interface{}{
			"name": name,
		},
	}

	return sm.storeStreamConfigInConsul(ctx, "hecate.nginx_stream_remove", state)
}

func (sm *StreamManager) storeStream(ctx context.Context, stream *StreamInfo) error {
	data, err := json.Marshal(stream)
	if err != nil {
		return err
	}

	_, err = sm.client.consul.KV().Put(&api.KVPair{
		Key:   fmt.Sprintf("hecate/streams/%s", stream.Name),
		Value: data,
	}, nil)

	return err
}

func (sm *StreamManager) deleteStreamFromConsul(ctx context.Context, name string) error {
	_, err := sm.client.consul.KV().Delete(fmt.Sprintf("hecate/streams/%s", name), nil)
	return err
}

func (sm *StreamManager) getAvailablePresets() []string {
	return []string{
		"mailcow",
		"jenkins", 
		"wazuh",
		"postgresql",
		"mysql",
		"redis",
		"minecraft",
		"teamspeak",
	}
}

// storeStreamConfigInConsul stores stream configuration in Consul KV for administrator review
func (sm *StreamManager) storeStreamConfigInConsul(ctx context.Context, operation string, config map[string]interface{}) error {
	logger := otelzap.Ctx(ctx)
	
	// Create configuration entry with metadata
	configEntry := map[string]interface{}{
		"operation":   operation,
		"config":      config,
		"created_at":  time.Now().UTC(),
		"status":      "pending_admin_review",
		"description": fmt.Sprintf("Stream %s operation requires administrator intervention", operation),
	}
	
	// Marshal configuration to JSON
	configJSON, err := json.Marshal(configEntry)
	if err != nil {
		return fmt.Errorf("failed to marshal stream configuration: %w", err)
	}
	
	// Store in Consul KV
	consulKey := fmt.Sprintf("hecate/stream-operations/%s-%d", operation, time.Now().Unix())
	_, err = sm.client.consul.KV().Put(&api.KVPair{
		Key:   consulKey,
		Value: configJSON,
	}, nil)
	
	if err != nil {
		return fmt.Errorf("failed to store stream configuration in Consul: %w", err)
	}
	
	logger.Info("Stream configuration stored in Consul for administrator review",
		zap.String("consul_key", consulKey),
		zap.String("operation", operation))
	
	return nil
}