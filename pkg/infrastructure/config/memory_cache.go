// Package config provides infrastructure implementations for configuration management
package config

import (
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/config"
	"go.uber.org/zap"
)

// MemoryCache implements config.Cache using in-memory storage
type MemoryCache struct {
	data   map[string]cacheEntry
	mutex  sync.RWMutex
	stats  config.CacheStats
	logger *zap.Logger
}

type cacheEntry struct {
	config   config.CachedConfig
	expireAt time.Time
}

// NewMemoryCache creates a new memory-based cache
func NewMemoryCache(logger *zap.Logger) config.Cache {
	return &MemoryCache{
		data:   make(map[string]cacheEntry),
		logger: logger.Named("config.memory_cache"),
	}
}

// Get retrieves a cached configuration
func (c *MemoryCache) Get(key string) (config.CachedConfig, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.data[key]
	if !exists {
		c.stats.Misses++
		return config.CachedConfig{}, false
	}

	// Check if expired
	if !entry.expireAt.IsZero() && time.Now().After(entry.expireAt) {
		c.mutex.RUnlock()
		c.mutex.Lock()
		delete(c.data, key)
		c.stats.Evictions++
		c.mutex.Unlock()
		c.mutex.RLock()
		
		c.stats.Misses++
		return config.CachedConfig{}, false
	}

	c.stats.Hits++
	c.logger.Debug("Cache hit",
		zap.String("key", key))

	return entry.config, true
}

// Set stores a configuration in cache
func (c *MemoryCache) Set(key string, conf config.CachedConfig) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Calculate expiry (if needed)
	var expireAt time.Time
	// For now, no expiry. In a real implementation, you might want TTL

	entry := cacheEntry{
		config:   conf,
		expireAt: expireAt,
	}

	c.data[key] = entry
	c.stats.Entries = int(len(c.data))

	c.logger.Debug("Configuration cached",
		zap.String("key", key),
		zap.String("format", string(conf.Format)))

	return nil
}

// Delete removes a configuration from cache
func (c *MemoryCache) Delete(key string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, exists := c.data[key]; exists {
		delete(c.data, key)
		c.stats.Entries = int(len(c.data))
		c.stats.Evictions++

		c.logger.Debug("Configuration removed from cache",
			zap.String("key", key))
	}

	return nil
}

// Clear clears all cached configurations
func (c *MemoryCache) Clear() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	count := len(c.data)
	c.data = make(map[string]cacheEntry)
	c.stats.Entries = 0
	c.stats.Evictions += int64(count)

	c.logger.Info("Cache cleared",
		zap.Int("cleared_entries", count))

	return nil
}

// Stats returns cache statistics
func (c *MemoryCache) Stats() config.CacheStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Calculate size estimate
	var sizeBytes int64
	for k := range c.data {
		// Rough estimate - in practice you'd want more accurate sizing
		sizeBytes += int64(len(k)) + 1024 // Estimate 1KB per config
	}

	stats := c.stats
	stats.Entries = len(c.data)
	stats.SizeBytes = sizeBytes

	return stats
}