// pkg/consul/kv/watch.go
//
// Consul KV Watch - Configuration Change Monitoring
//
// This module provides watch capabilities for Consul KV, allowing applications
// to react to configuration changes in real-time.
//
// Design Principles:
// - Non-blocking watch goroutines
// - Automatic reconnection on errors
// - Graceful shutdown via context cancellation
// - Callback-based notification
// - Watch single keys or entire prefixes
//
// Usage Pattern:
//   1. Create watcher for key or prefix
//   2. Provide callback for change notifications
//   3. Watch runs in background until context canceled
//   4. Callback receives new value on each change

package kv

import (
	"context"
	"fmt"
	"time"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// WatchCallback is called when a watched key changes
//
// Parameters:
//   - key: The key that changed
//   - value: New value (empty string if deleted)
//   - exists: Whether key exists (false if deleted)
//
// Return error to stop the watch (non-fatal errors should be logged, not returned)
type WatchCallback func(key string, value string, exists bool) error

// PrefixWatchCallback is called when any key under a prefix changes
//
// Parameters:
//   - changes: Map of key → value for all changed keys
//
// Return error to stop the watch
type PrefixWatchCallback func(changes map[string]string) error

// Watcher manages Consul KV watches
type Watcher struct {
	client *consulapi.Client
	ctx    context.Context
	logger otelzap.LoggerWithCtx
}

// NewWatcher creates a new Consul KV watcher
func NewWatcher(ctx context.Context, client *consulapi.Client) *Watcher {
	return &Watcher{
		client: client,
		ctx:    ctx,
		logger: otelzap.Ctx(ctx),
	}
}

// WatchKey watches a single Consul KV key for changes
//
// Runs in a background goroutine until context is canceled.
// Automatically reconnects on errors with exponential backoff.
//
// Parameters:
//   - key: KV key to watch (e.g., "config/eos/log-level")
//   - callback: Called when key changes
//
// Example:
//
//	watcher := kv.NewWatcher(ctx, consulClient)
//	go watcher.WatchKey("config/eos/log-level", func(key, value string, exists bool) error {
//	    if exists {
//	        logger.Info("Config changed", zap.String("key", key), zap.String("value", value))
//	        // Apply new config
//	        setLogLevel(value)
//	    } else {
//	        logger.Info("Config deleted", zap.String("key", key))
//	        // Revert to default
//	        setLogLevel("info")
//	    }
//	    return nil
//	})
func (w *Watcher) WatchKey(key string, callback WatchCallback) {
	w.logger.Info("Starting watch on Consul KV key",
		zap.String("key", key))

	var waitIndex uint64
	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-w.ctx.Done():
			w.logger.Info("Watch canceled",
				zap.String("key", key),
				zap.String("reason", w.ctx.Err().Error()))
			return

		default:
			// Query with blocking query (long poll)
			queryOpts := &consulapi.QueryOptions{
				WaitIndex: waitIndex,
				WaitTime:  5 * time.Minute, // Long poll timeout
			}

			pair, meta, err := w.client.KV().Get(key, queryOpts)
			if err != nil {
				w.logger.Warn("Watch query failed, retrying",
					zap.String("key", key),
					zap.Error(err),
					zap.Duration("backoff", backoff))

				// Exponential backoff on errors
				time.Sleep(backoff)
				backoff = min(backoff*2, maxBackoff)
				continue
			}

			// Reset backoff on successful query
			backoff = time.Second

			// Check if data changed (waitIndex advances)
			if meta.LastIndex != waitIndex {
				waitIndex = meta.LastIndex

				// Extract value
				var value string
				exists := (pair != nil)
				if exists {
					value = string(pair.Value)
				}

				w.logger.Debug("Config change detected",
					zap.String("key", key),
					zap.Bool("exists", exists),
					zap.Int("value_length", len(value)),
					zap.Uint64("index", waitIndex))

				// Call user callback
				if err := callback(key, value, exists); err != nil {
					w.logger.Error("Watch callback failed, stopping watch",
						zap.String("key", key),
						zap.Error(err))
					return
				}
			}
		}
	}
}

// WatchPrefix watches all keys under a prefix for changes
//
// Runs in a background goroutine until context is canceled.
// Calls callback with ALL keys under prefix when ANY key changes.
//
// Parameters:
//   - prefix: KV prefix to watch (e.g., "config/bionicgpt/")
//   - callback: Called when any key under prefix changes
//
// Example:
//
//	watcher := kv.NewWatcher(ctx, consulClient)
//	go watcher.WatchPrefix("config/bionicgpt/", func(changes map[string]string) error {
//	    logger.Info("Service config changed",
//	        zap.Int("config_count", len(changes)))
//
//	    // Reload entire config
//	    for key, value := range changes {
//	        logger.Debug("Config entry", zap.String("key", key), zap.String("value", value))
//	    }
//
//	    // Apply new config
//	    return applyConfig(changes)
//	})
func (w *Watcher) WatchPrefix(prefix string, callback PrefixWatchCallback) {
	w.logger.Info("Starting watch on Consul KV prefix",
		zap.String("prefix", prefix))

	var waitIndex uint64
	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-w.ctx.Done():
			w.logger.Info("Prefix watch canceled",
				zap.String("prefix", prefix),
				zap.String("reason", w.ctx.Err().Error()))
			return

		default:
			// Query with blocking query (long poll)
			queryOpts := &consulapi.QueryOptions{
				WaitIndex: waitIndex,
				WaitTime:  5 * time.Minute,
			}

			pairs, meta, err := w.client.KV().List(prefix, queryOpts)
			if err != nil {
				w.logger.Warn("Prefix watch query failed, retrying",
					zap.String("prefix", prefix),
					zap.Error(err),
					zap.Duration("backoff", backoff))

				time.Sleep(backoff)
				backoff = min(backoff*2, maxBackoff)
				continue
			}

			// Reset backoff on successful query
			backoff = time.Second

			// Check if data changed
			if meta.LastIndex != waitIndex {
				waitIndex = meta.LastIndex

				// Build changes map
				changes := make(map[string]string, len(pairs))
				for _, pair := range pairs {
					changes[pair.Key] = string(pair.Value)
				}

				w.logger.Debug("Prefix change detected",
					zap.String("prefix", prefix),
					zap.Int("key_count", len(changes)),
					zap.Uint64("index", waitIndex))

				// Call user callback
				if err := callback(changes); err != nil {
					w.logger.Error("Prefix watch callback failed, stopping watch",
						zap.String("prefix", prefix),
						zap.Error(err))
					return
				}
			}
		}
	}
}

// WatchMultipleKeys watches multiple keys simultaneously
//
// More efficient than starting separate watches for each key.
// Calls callback for each key that changes.
//
// Parameters:
//   - keys: List of keys to watch
//   - callback: Called for each key that changes
//
// Example:
//
//	keys := []string{
//	    "config/eos/log-level",
//	    "config/eos/telemetry-enabled",
//	    "config/eos/update-channel",
//	}
//	go watcher.WatchMultipleKeys(keys, func(key, value string, exists bool) error {
//	    logger.Info("Global config changed", zap.String("key", key), zap.String("value", value))
//	    return applyConfigChange(key, value)
//	})
func (w *Watcher) WatchMultipleKeys(keys []string, callback WatchCallback) {
	w.logger.Info("Starting multi-key watch",
		zap.Int("key_count", len(keys)))

	// Track last known values and indexes for each key
	lastValues := make(map[string]string, len(keys))
	lastIndexes := make(map[string]uint64, len(keys))

	// Initialize last values
	for _, key := range keys {
		pair, _, err := w.client.KV().Get(key, nil)
		if err == nil && pair != nil {
			lastValues[key] = string(pair.Value)
		}
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			w.logger.Info("Multi-key watch canceled",
				zap.String("reason", w.ctx.Err().Error()))
			return

		case <-ticker.C:
			// Check each key
			for _, key := range keys {
				queryOpts := &consulapi.QueryOptions{
					WaitIndex: lastIndexes[key],
					WaitTime:  1 * time.Second, // Short timeout for multi-key
				}

				pair, meta, err := w.client.KV().Get(key, queryOpts)
				if err != nil {
					w.logger.Warn("Multi-key watch query failed",
						zap.String("key", key),
						zap.Error(err))
					continue
				}

				// Check if changed
				if meta.LastIndex != lastIndexes[key] {
					lastIndexes[key] = meta.LastIndex

					var value string
					exists := (pair != nil)
					if exists {
						value = string(pair.Value)
					}

					// Only call callback if value actually changed
					if value != lastValues[key] {
						lastValues[key] = value

						w.logger.Debug("Multi-key change detected",
							zap.String("key", key),
							zap.Bool("exists", exists))

						if err := callback(key, value, exists); err != nil {
							w.logger.Error("Multi-key callback failed, stopping watch",
								zap.String("key", key),
								zap.Error(err))
							return
						}
					}
				}
			}
		}
	}
}

// WatchWithReload watches a key and calls reload function on change
//
// Convenience wrapper for the common pattern of reloading config on change.
//
// Parameters:
//   - key: Key to watch
//   - reloadFunc: Function to call on change (receives new value)
//
// Example:
//
//	go watcher.WatchWithReload("config/eos/log-level", func(value string) error {
//	    level, err := zapcore.ParseLevel(value)
//	    if err != nil {
//	        return fmt.Errorf("invalid log level: %w", err)
//	    }
//	    logger.SetLevel(level)
//	    logger.Info("Log level updated", zap.String("level", value))
//	    return nil
//	})
func (w *Watcher) WatchWithReload(key string, reloadFunc func(string) error) {
	callback := func(k string, value string, exists bool) error {
		if !exists {
			w.logger.Warn("Config key deleted, skipping reload",
				zap.String("key", k))
			return nil
		}

		w.logger.Info("Reloading config",
			zap.String("key", k),
			zap.String("value", value))

		if err := reloadFunc(value); err != nil {
			return fmt.Errorf("reload failed for key %s: %w", k, err)
		}

		return nil
	}

	w.WatchKey(key, callback)
}

// WatchServiceConfig watches all config for a service and reloads on change
//
// Watches the entire service prefix (config/[service]/) and provides
// the complete config map to the reload function.
//
// Parameters:
//   - service: Service name
//   - reloadFunc: Function to call with complete config on any change
//
// Example:
//
//	go watcher.WatchServiceConfig("bionicgpt", func(config map[string]string) error {
//	    logger.Info("BionicGPT config changed",
//	        zap.Int("config_count", len(config)))
//
//	    // Parse config
//	    enableRAG := config["config/bionicgpt/feature_flags/enable_rag"] == "true"
//	    logLevel := config["config/bionicgpt/log_level"]
//
//	    // Apply config
//	    return applyServiceConfig(enableRAG, logLevel)
//	})
func (w *Watcher) WatchServiceConfig(service string, reloadFunc func(map[string]string) error) {
	prefix := ServicePath(service)

	callback := func(changes map[string]string) error {
		w.logger.Info("Service config changed",
			zap.String("service", service),
			zap.Int("config_count", len(changes)))

		if err := reloadFunc(changes); err != nil {
			return fmt.Errorf("service config reload failed: %w", err)
		}

		return nil
	}

	w.WatchPrefix(prefix, callback)
}

// min returns the smaller of two durations
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
