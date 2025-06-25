// pkg/delphi/queue.go - Redis Streams implementation for Delphi pipeline
package delphi

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// StreamMessage represents a message in the Delphi pipeline
type StreamMessage struct {
	AlertID   string                 `json:"alert_id"`
	Stage     string                 `json:"stage"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
	Retry     int                    `json:"retry,omitempty"`
}

// StreamHandler manages Redis streams for the Delphi pipeline
type StreamHandler struct {
	client        *redis.Client
	consumerGroup string
	streams       map[string]string
	logger        *zap.Logger
}

// NewStreamHandler creates a new Redis stream handler
func NewStreamHandler(redisURL, consumerGroup string, logger *zap.Logger) (*StreamHandler, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	streams := map[string]string{
		"new_alert":       "delphi:alerts:new",
		"agent_enriched":  "delphi:alerts:enriched",
		"new_response":    "delphi:alerts:analyzed",
		"alert_structured": "delphi:alerts:structured",
		"alert_formatted": "delphi:alerts:formatted",
	}

	sh := &StreamHandler{
		client:        client,
		consumerGroup: consumerGroup,
		streams:       streams,
		logger:        logger,
	}

	// Initialize consumer groups
	if err := sh.initConsumerGroups(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize consumer groups: %w", err)
	}

	return sh, nil
}

// initConsumerGroups creates consumer groups for all streams
func (sh *StreamHandler) initConsumerGroups(ctx context.Context) error {
	for _, streamName := range sh.streams {
		err := sh.client.XGroupCreateMkStream(ctx, streamName, sh.consumerGroup, "0").Err()
		if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
			sh.logger.Error("Failed to create consumer group",
				zap.String("stream", streamName),
				zap.String("group", sh.consumerGroup),
				zap.Error(err))
			return err
		}
		
		sh.logger.Debug("Consumer group initialized",
			zap.String("stream", streamName),
			zap.String("group", sh.consumerGroup))
	}
	return nil
}

// PublishMessage sends a message to the specified stream
func (sh *StreamHandler) PublishMessage(ctx context.Context, channel string, msg *StreamMessage) error {
	streamName, exists := sh.streams[channel]
	if !exists {
		return fmt.Errorf("unknown channel: %s", channel)
	}

	msg.Timestamp = time.Now()
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	fields := map[string]interface{}{
		"alert_id": msg.AlertID,
		"stage":    msg.Stage,
		"data":     string(data),
		"retry":    msg.Retry,
	}

	messageID, err := sh.client.XAdd(ctx, &redis.XAddArgs{
		Stream: streamName,
		Values: fields,
	}).Result()

	if err != nil {
		sh.logger.Error("Failed to publish message",
			zap.String("stream", streamName),
			zap.String("alert_id", msg.AlertID),
			zap.Error(err))
		return err
	}

	sh.logger.Debug("Message published",
		zap.String("stream", streamName),
		zap.String("message_id", messageID),
		zap.String("alert_id", msg.AlertID),
		zap.String("stage", msg.Stage))

	return nil
}

// ConsumeMessages consumes messages from the specified stream
func (sh *StreamHandler) ConsumeMessages(ctx context.Context, channel, consumerName string, handler MessageHandler) error {
	streamName, exists := sh.streams[channel]
	if !exists {
		return fmt.Errorf("unknown channel: %s", channel)
	}

	sh.logger.Info("Starting message consumer",
		zap.String("stream", streamName),
		zap.String("consumer", consumerName),
		zap.String("group", sh.consumerGroup))

	for {
		select {
		case <-ctx.Done():
			sh.logger.Info("Consumer context cancelled",
				zap.String("consumer", consumerName))
			return ctx.Err()
		default:
			messages, err := sh.client.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    sh.consumerGroup,
				Consumer: consumerName,
				Streams:  []string{streamName, ">"},
				Count:    10,
				Block:    5 * time.Second,
			}).Result()

			if err != nil {
				if err == redis.Nil {
					continue // No messages, retry
				}
				sh.logger.Error("Failed to read from stream",
					zap.String("stream", streamName),
					zap.String("consumer", consumerName),
					zap.Error(err))
				time.Sleep(time.Second)
				continue
			}

			for _, stream := range messages {
				for _, message := range stream.Messages {
					if err := sh.processMessage(ctx, streamName, message, handler); err != nil {
						sh.logger.Error("Failed to process message",
							zap.String("message_id", message.ID),
							zap.String("stream", streamName),
							zap.Error(err))
						// Don't acknowledge failed messages - they'll be retried
						continue
					}

					// Acknowledge successful processing
					if err := sh.client.XAck(ctx, streamName, sh.consumerGroup, message.ID).Err(); err != nil {
						sh.logger.Error("Failed to acknowledge message",
							zap.String("message_id", message.ID),
							zap.Error(err))
					}
				}
			}
		}
	}
}

// processMessage handles individual message processing
func (sh *StreamHandler) processMessage(ctx context.Context, streamName string, message redis.XMessage, handler MessageHandler) error {
	alertID, ok := message.Values["alert_id"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid alert_id in message")
	}

	dataStr, ok := message.Values["data"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid data in message")
	}

	var streamMsg StreamMessage
	if err := json.Unmarshal([]byte(dataStr), &streamMsg); err != nil {
		return fmt.Errorf("failed to unmarshal message data: %w", err)
	}

	sh.logger.Debug("Processing message",
		zap.String("message_id", message.ID),
		zap.String("alert_id", alertID),
		zap.String("stage", streamMsg.Stage))

	return handler.HandleMessage(ctx, &streamMsg)
}

// GetPendingMessages retrieves messages that were delivered but not acknowledged
func (sh *StreamHandler) GetPendingMessages(ctx context.Context, channel, consumerName string) ([]redis.XMessage, error) {
	streamName, exists := sh.streams[channel]
	if !exists {
		return nil, fmt.Errorf("unknown channel: %s", channel)
	}

	pending, err := sh.client.XPending(ctx, streamName, sh.consumerGroup).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get pending messages: %w", err)
	}

	if pending.Count == 0 {
		return nil, nil
	}

	// Get detailed pending messages
	result, err := sh.client.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream: streamName,
		Group:  sh.consumerGroup,
		Start:  "-",
		End:    "+",
		Count:  100,
	}).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to get pending message details: %w", err)
	}

	var messages []redis.XMessage
	for _, pending := range result {
		// Claim messages that have been idle for more than 30 seconds
		if pending.Idle > 30*time.Second {
			claimed, err := sh.client.XClaim(ctx, &redis.XClaimArgs{
				Stream:   streamName,
				Group:    sh.consumerGroup,
				Consumer: consumerName,
				MinIdle:  30 * time.Second,
				Messages: []string{pending.ID},
			}).Result()
			
			if err != nil {
				sh.logger.Error("Failed to claim pending message",
					zap.String("message_id", pending.ID),
					zap.Error(err))
				continue
			}
			
			messages = append(messages, claimed...)
		}
	}

	return messages, nil
}

// Close closes the Redis connection
func (sh *StreamHandler) Close() error {
	return sh.client.Close()
}

// MessageHandler interface for processing stream messages
type MessageHandler interface {
	HandleMessage(ctx context.Context, msg *StreamMessage) error
}

// MessageHandlerFunc is an adapter to allow functions to be used as MessageHandlers
type MessageHandlerFunc func(ctx context.Context, msg *StreamMessage) error

func (f MessageHandlerFunc) HandleMessage(ctx context.Context, msg *StreamMessage) error {
	return f(ctx, msg)
}

// HybridMessageBus supports both PostgreSQL and Redis for gradual migration
type HybridMessageBus struct {
	useRedis      bool
	streamHandler *StreamHandler
	// PostgreSQL handler would be added here
	logger        *zap.Logger
}

// NewHybridMessageBus creates a message bus that can use either transport
func NewHybridMessageBus(useRedis bool, streamHandler *StreamHandler, logger *zap.Logger) *HybridMessageBus {
	return &HybridMessageBus{
		useRedis:      useRedis,
		streamHandler: streamHandler,
		logger:        logger,
	}
}

// PublishMessage sends a message via the active transport
func (hmb *HybridMessageBus) PublishMessage(ctx context.Context, channel string, msg *StreamMessage) error {
	if hmb.useRedis && hmb.streamHandler != nil {
		return hmb.streamHandler.PublishMessage(ctx, channel, msg)
	}
	
	// Fallback to PostgreSQL NOTIFY (implementation would go here)
	hmb.logger.Warn("Redis not available, falling back to PostgreSQL NOTIFY",
		zap.String("channel", channel),
		zap.String("alert_id", msg.AlertID))
	
	// TODO: Implement PostgreSQL fallback
	return fmt.Errorf("PostgreSQL fallback not yet implemented")
}

// ConsumeMessages consumes messages via the active transport
func (hmb *HybridMessageBus) ConsumeMessages(ctx context.Context, channel, consumerName string, handler MessageHandler) error {
	if hmb.useRedis && hmb.streamHandler != nil {
		return hmb.streamHandler.ConsumeMessages(ctx, channel, consumerName, handler)
	}
	
	// Fallback to PostgreSQL LISTEN (implementation would go here)
	hmb.logger.Warn("Redis not available, falling back to PostgreSQL LISTEN",
		zap.String("channel", channel),
		zap.String("consumer", consumerName))
	
	// TODO: Implement PostgreSQL fallback
	return fmt.Errorf("PostgreSQL fallback not yet implemented")
}