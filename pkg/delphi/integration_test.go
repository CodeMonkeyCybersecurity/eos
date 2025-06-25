package delphi

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap/zaptest"
)

// TestRedisContainer manages a Redis container for testing
type TestRedisContainer struct {
	container testcontainers.Container
	host      string
	port      string
}

// NewTestRedisContainer creates a new Redis container for testing
func NewTestRedisContainer(ctx context.Context) (*TestRedisContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:        "redis:7-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections"),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	host, err := container.Host(ctx)
	if err != nil {
		return nil, err
	}

	port, err := container.MappedPort(ctx, "6379")
	if err != nil {
		return nil, err
	}

	return &TestRedisContainer{
		container: container,
		host:      host,
		port:      port.Port(),
	}, nil
}

// GetConnectionString returns the Redis connection string
func (trc *TestRedisContainer) GetConnectionString() string {
	return fmt.Sprintf("redis://%s:%s/0", trc.host, trc.port)
}

// Close terminates the container
func (trc *TestRedisContainer) Close(ctx context.Context) error {
	return trc.container.Terminate(ctx)
}

// TestQueueIntegration tests the Redis queue implementation
func TestQueueIntegration(t *testing.T) {
	ctx := context.Background()
	logger := zaptest.NewLogger(t)

	// Start Redis container
	redisContainer, err := NewTestRedisContainer(ctx)
	require.NoError(t, err)
	defer redisContainer.Close(ctx)

	// Create stream handler
	streamHandler, err := NewStreamHandler(
		redisContainer.GetConnectionString(),
		"test-group",
		logger,
	)
	require.NoError(t, err)
	defer streamHandler.Close()

	t.Run("PublishAndConsume", func(t *testing.T) {
		// Test message publishing and consumption
		testMsg := &StreamMessage{
			AlertID:   "test-alert-1",
			Stage:     "test-stage",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"test_field": "test_value",
				"alert": map[string]interface{}{
					"id":    "test-alert-1",
					"level": 10,
				},
			},
		}

		// Publish message
		err := streamHandler.PublishMessage(ctx, "new_alert", testMsg)
		require.NoError(t, err)

		// Consume message
		messageReceived := make(chan *StreamMessage, 1)
		handler := MessageHandlerFunc(func(ctx context.Context, msg *StreamMessage) error {
			messageReceived <- msg
			return nil
		})

		// Start consumer in goroutine
		go func() {
			streamHandler.ConsumeMessages(ctx, "new_alert", "test-consumer", handler)
		}()

		// Wait for message
		select {
		case receivedMsg := <-messageReceived:
			assert.Equal(t, testMsg.AlertID, receivedMsg.AlertID)
			assert.Equal(t, testMsg.Stage, receivedMsg.Stage)
			assert.Equal(t, testMsg.Data["test_field"], receivedMsg.Data["test_field"])
		case <-time.After(10 * time.Second):
			t.Fatal("Timeout waiting for message")
		}
	})

	t.Run("MessagePersistence", func(t *testing.T) {
		// Test that messages persist across consumer restarts
		testMsg := &StreamMessage{
			AlertID:   "persistent-alert",
			Stage:     "persistence-test",
			Timestamp: time.Now(),
			Data:      map[string]interface{}{"persistent": true},
		}

		// Publish message
		err := streamHandler.PublishMessage(ctx, "new_alert", testMsg)
		require.NoError(t, err)

		// Create new consumer after message is published
		messageReceived := make(chan *StreamMessage, 1)
		handler := MessageHandlerFunc(func(ctx context.Context, msg *StreamMessage) error {
			messageReceived <- msg
			return nil
		})

		consumerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		go func() {
			streamHandler.ConsumeMessages(consumerCtx, "new_alert", "persistent-consumer", handler)
		}()

		// Message should be received even though consumer started after publish
		select {
		case receivedMsg := <-messageReceived:
			assert.Equal(t, testMsg.AlertID, receivedMsg.AlertID)
		case <-time.After(10 * time.Second):
			t.Fatal("Timeout waiting for persistent message")
		}
	})
}

// TestCircuitBreakerIntegration tests the circuit breaker implementation
func TestCircuitBreakerIntegration(t *testing.T) {
	ctx := context.Background()
	logger := zaptest.NewLogger(t)

	// Start Redis container
	redisContainer, err := NewTestRedisContainer(ctx)
	require.NoError(t, err)
	defer redisContainer.Close(ctx)

	// Create Redis client
	opts, err := redis.ParseURL(redisContainer.GetConnectionString())
	require.NoError(t, err)
	client := redis.NewClient(opts)
	defer client.Close()

	t.Run("CircuitBreakerFlow", func(t *testing.T) {
		config := CircuitBreakerConfig{
			Name:               "test-cb",
			FailureThreshold:   3,
			SuccessThreshold:   2,
			Timeout:            100 * time.Millisecond,
			MaxConcurrentCalls: 1,
		}

		cb := NewCircuitBreaker(config, client, logger)

		// Test 1: Circuit should be closed initially
		stats := cb.GetStats(ctx)
		assert.Equal(t, StateClosed, stats.State)

		// Test 2: Successful calls should keep circuit closed
		err := cb.Execute(ctx, func() error {
			return nil // Success
		})
		assert.NoError(t, err)

		stats = cb.GetStats(ctx)
		assert.Equal(t, StateClosed, stats.State)

		// Test 3: Multiple failures should open circuit
		for i := 0; i < 3; i++ {
			err := cb.Execute(ctx, func() error {
				return fmt.Errorf("simulated failure %d", i)
			})
			assert.Error(t, err)
		}

		stats = cb.GetStats(ctx)
		assert.Equal(t, StateOpen, stats.State)
		assert.Equal(t, int64(3), stats.FailureCount)

		// Test 4: Calls should be rejected when circuit is open
		err = cb.Execute(ctx, func() error {
			return nil
		})
		assert.Error(t, err)
		assert.True(t, IsCircuitOpen(err))

		// Test 5: Circuit should transition to half-open after timeout
		time.Sleep(150 * time.Millisecond) // Wait for timeout

		// First call should transition to half-open
		err = cb.Execute(ctx, func() error {
			return nil // Success
		})
		assert.NoError(t, err)

		// Test 6: Successful calls in half-open should close circuit
		err = cb.Execute(ctx, func() error {
			return nil // Another success
		})
		assert.NoError(t, err)

		stats = cb.GetStats(ctx)
		assert.Equal(t, StateClosed, stats.State)
	})

	t.Run("CircuitBreakerConcurrency", func(t *testing.T) {
		config := CircuitBreakerConfig{
			Name:               "concurrent-cb",
			FailureThreshold:   5,
			SuccessThreshold:   3,
			Timeout:            50 * time.Millisecond,
			MaxConcurrentCalls: 2,
		}

		cb := NewCircuitBreaker(config, client, logger)

		// Open the circuit
		for i := 0; i < 5; i++ {
			cb.Execute(ctx, func() error {
				return fmt.Errorf("failure %d", i)
			})
		}

		// Wait for transition to half-open
		time.Sleep(60 * time.Millisecond)

		// Test concurrent call limiting in half-open state
		results := make(chan error, 5)

		for i := 0; i < 5; i++ {
			go func(id int) {
				err := cb.Execute(ctx, func() error {
					time.Sleep(10 * time.Millisecond) // Simulate work
					return nil
				})
				results <- err
			}(i)
		}

		// Collect results
		var errors []error
		for i := 0; i < 5; i++ {
			err := <-results
			if err != nil {
				errors = append(errors, err)
			}
		}

		// Should have some circuit open errors due to concurrency limit
		assert.Greater(t, len(errors), 0, "Expected some requests to be rejected due to concurrency limit")
	})
}

// TestWorkerIntegration tests the enhanced worker implementation
func TestWorkerIntegration(t *testing.T) {
	ctx := context.Background()
	logger := zaptest.NewLogger(t)

	// Start Redis container
	redisContainer, err := NewTestRedisContainer(ctx)
	require.NoError(t, err)
	defer redisContainer.Close(ctx)

	t.Run("WorkerProcessing", func(t *testing.T) {
		// Create test processor
		processor := &TestAlertProcessor{
			processFunc: func(ctx context.Context, alert *Alert) (*Alert, error) {
				// Simulate processing by adding a field
				alert.Data["processed"] = true
				alert.Data["processor"] = "test-processor"
				alert.Stage = "processed"
				return alert, nil
			},
		}

		// Create worker config
		config := DefaultWorkerConfig("test-worker", "new")
		config.RedisURL = redisContainer.GetConnectionString()
		config.EnableCircuitBreaker = false // Disable for simpler test

		// Create enhanced worker
		worker, err := NewEnhancedWorker(config, processor, logger)
		require.NoError(t, err)
		defer worker.Stop(ctx)

		// Create test alert
		testAlert := &Alert{
			ID:        "test-alert-worker",
			Stage:     "new",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"original": "data",
			},
			State:   "new",
			Version: 1,
		}

		// Publish test message
		msg := &StreamMessage{
			AlertID:   testAlert.ID,
			Stage:     "new",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"alert": testAlert,
			},
		}

		err = worker.streamHandler.PublishMessage(ctx, "new_alert", msg)
		require.NoError(t, err)

		// Start worker in background
		workerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		go func() {
			worker.Start(workerCtx)
		}()

		// Wait a bit for processing
		time.Sleep(2 * time.Second)

		// Verify processing occurred
		assert.True(t, processor.called, "Processor should have been called")
		assert.Equal(t, testAlert.ID, processor.lastAlert.ID)
		assert.True(t, processor.lastAlert.Data["processed"].(bool))
	})
}

// TestAlertProcessor is a test implementation of AlertProcessor
type TestAlertProcessor struct {
	processFunc func(ctx context.Context, alert *Alert) (*Alert, error)
	called      bool
	lastAlert   *Alert
}

func (tap *TestAlertProcessor) ProcessAlert(ctx context.Context, alert *Alert) (*Alert, error) {
	tap.called = true
	tap.lastAlert = alert
	if tap.processFunc != nil {
		return tap.processFunc(ctx, alert)
	}
	return alert, nil
}

func (tap *TestAlertProcessor) GetProcessorName() string {
	return "test-processor"
}

func (tap *TestAlertProcessor) ValidateAlert(alert *Alert) error {
	if alert == nil {
		return fmt.Errorf("alert is nil")
	}
	if alert.ID == "" {
		return fmt.Errorf("alert ID is empty")
	}
	return nil
}

// BenchmarkQueueThroughput benchmarks the queue throughput
func BenchmarkQueueThroughput(b *testing.B) {
	ctx := context.Background()
	logger := zaptest.NewLogger(b)

	// Start Redis container
	redisContainer, err := NewTestRedisContainer(ctx)
	require.NoError(b, err)
	defer redisContainer.Close(ctx)

	// Create stream handler
	streamHandler, err := NewStreamHandler(
		redisContainer.GetConnectionString(),
		"bench-group",
		logger,
	)
	require.NoError(b, err)
	defer streamHandler.Close()

	b.ResetTimer()

	b.Run("PublishThroughput", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			msg := &StreamMessage{
				AlertID:   fmt.Sprintf("bench-alert-%d", i),
				Stage:     "benchmark",
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"benchmark": true,
					"iteration": i,
				},
			}

			err := streamHandler.PublishMessage(ctx, "new_alert", msg)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ConsumeWithProcessing", func(b *testing.B) {
		// Pre-populate queue
		for i := 0; i < b.N; i++ {
			msg := &StreamMessage{
				AlertID:   fmt.Sprintf("consume-alert-%d", i),
				Stage:     "benchmark",
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"benchmark": true,
					"iteration": i,
				},
			}
			streamHandler.PublishMessage(ctx, "new_alert", msg)
		}

		b.ResetTimer()

		processed := 0
		handler := MessageHandlerFunc(func(ctx context.Context, msg *StreamMessage) error {
			// Simulate light processing
			_ = json.Marshal(msg.Data)
			processed++
			return nil
		})

		// Start consumer
		consumerCtx, cancel := context.WithCancel(ctx)
		go func() {
			streamHandler.ConsumeMessages(consumerCtx, "new_alert", "bench-consumer", handler)
		}()

		// Wait for all messages to be processed
		for processed < b.N {
			time.Sleep(10 * time.Millisecond)
		}

		cancel()
	})
}

// TestEndToEndPipeline tests the complete pipeline flow
func TestEndToEndPipeline(t *testing.T) {
	ctx := context.Background()
	logger := zaptest.NewLogger(t)

	// Start Redis container
	redisContainer, err := NewTestRedisContainer(ctx)
	require.NoError(t, err)
	defer redisContainer.Close(ctx)

	// Create processors for each stage
	enricher := &TestAlertProcessor{
		processFunc: func(ctx context.Context, alert *Alert) (*Alert, error) {
			alert.Data["enriched"] = true
			alert.Stage = "enriched"
			return alert, nil
		},
	}

	analyzer := &TestAlertProcessor{
		processFunc: func(ctx context.Context, alert *Alert) (*Alert, error) {
			alert.Data["analyzed"] = true
			alert.Stage = "analyzed"
			return alert, nil
		},
	}

	formatter := &TestAlertProcessor{
		processFunc: func(ctx context.Context, alert *Alert) (*Alert, error) {
			alert.Data["formatted"] = true
			alert.Stage = "formatted"
			return alert, nil
		},
	}

	// Create workers for each stage
	enricherConfig := DefaultWorkerConfig("enricher", "new")
	enricherConfig.RedisURL = redisContainer.GetConnectionString()
	enricherConfig.EnableCircuitBreaker = false

	analyzerConfig := DefaultWorkerConfig("analyzer", "enriched")
	analyzerConfig.RedisURL = redisContainer.GetConnectionString()
	analyzerConfig.EnableCircuitBreaker = false

	formatterConfig := DefaultWorkerConfig("formatter", "analyzed")
	formatterConfig.RedisURL = redisContainer.GetConnectionString()
	formatterConfig.EnableCircuitBreaker = false

	enricherWorker, err := NewEnhancedWorker(enricherConfig, enricher, logger)
	require.NoError(t, err)
	defer enricherWorker.Stop(ctx)

	analyzerWorker, err := NewEnhancedWorker(analyzerConfig, analyzer, logger)
	require.NoError(t, err)
	defer analyzerWorker.Stop(ctx)

	formatterWorker, err := NewEnhancedWorker(formatterConfig, formatter, logger)
	require.NoError(t, err)
	defer formatterWorker.Stop(ctx)

	// Start all workers
	workerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	go enricherWorker.Start(workerCtx)
	go analyzerWorker.Start(workerCtx)
	go formatterWorker.Start(workerCtx)

	// Create and inject initial alert
	testAlert := &Alert{
		ID:        "e2e-test-alert",
		Stage:     "new",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"original": "data",
		},
		State:   "new",
		Version: 1,
	}

	msg := &StreamMessage{
		AlertID:   testAlert.ID,
		Stage:     "new",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"alert": testAlert,
		},
	}

	err = enricherWorker.streamHandler.PublishMessage(ctx, "new_alert", msg)
	require.NoError(t, err)

	// Wait for pipeline to complete
	time.Sleep(5 * time.Second)

	// Verify all processors were called
	assert.True(t, enricher.called, "Enricher should have been called")
	assert.True(t, analyzer.called, "Analyzer should have been called")
	assert.True(t, formatter.called, "Formatter should have been called")

	// Verify data flow
	if formatter.lastAlert != nil {
		assert.True(t, formatter.lastAlert.Data["enriched"].(bool))
		assert.True(t, formatter.lastAlert.Data["analyzed"].(bool))
		assert.True(t, formatter.lastAlert.Data["formatted"].(bool))
	}
}
