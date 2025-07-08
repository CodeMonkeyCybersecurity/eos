package config

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// service implements the Service interface
type service struct {
	repository Repository
	parser     Parser
	validator  Validator
	encryptor  Encryptor
	cache      Cache

	// Active watchers
	watchers   map[string]Watcher
	watchMutex sync.Mutex

	logger *zap.Logger
}

// NewService creates a new configuration service
func NewService(
	repository Repository,
	parser Parser,
	validator Validator,
	encryptor Encryptor,
	cache Cache,
	logger *zap.Logger,
) Service {
	return &service{
		repository: repository,
		parser:     parser,
		validator:  validator,
		encryptor:  encryptor,
		cache:      cache,
		watchers:   make(map[string]Watcher),
		logger:     logger.Named("config"),
	}
}

// LoadFile loads configuration from a file into the target struct
func (s *service) LoadFile(ctx context.Context, path string, target interface{}) error {
	return s.LoadWithDefaults(ctx, path, target, nil)
}

// LoadWithDefaults loads config and applies defaults for missing values
func (s *service) LoadWithDefaults(ctx context.Context, path string, target interface{}, defaults map[string]interface{}) error {
	s.logger.Info("Loading configuration file",
		zap.String("path", path),
		zap.Bool("has_defaults", defaults != nil))

	// Check cache first
	if s.cache != nil {
		if cached, ok := s.cache.Get(path); ok {
			s.logger.Debug("Using cached configuration",
				zap.String("path", path),
				zap.Time("loaded_at", cached.LoadedAt))

			// Check if file has been modified
			info, err := s.repository.Stat(ctx, path)
			if err == nil && !info.ModTime.After(cached.ModTime) {
				return s.unmarshalInto(cached.Data, target)
			}
		}
	}

	// Check if file exists
	exists, err := s.repository.Exists(ctx, path)
	if err != nil {
		return &ConfigError{
			Type:    ErrorLoad,
			Path:    path,
			Message: "failed to check file existence",
			Cause:   err,
		}
	}

	if !exists {
		return &ConfigError{
			Type:    ErrorNotFound,
			Path:    path,
			Message: "configuration file not found",
		}
	}

	// Read raw data
	data, err := s.repository.Read(ctx, path)
	if err != nil {
		return &ConfigError{
			Type:    ErrorLoad,
			Path:    path,
			Message: "failed to read configuration file",
			Cause:   err,
		}
	}

	// Check if encrypted
	if s.encryptor != nil && s.encryptor.IsEncrypted(ctx, data) {
		decrypted, err := s.encryptor.Decrypt(ctx, data)
		if err != nil {
			return &ConfigError{
				Type:    ErrorEncryption,
				Path:    path,
				Message: "failed to decrypt configuration",
				Cause:   err,
			}
		}
		data = decrypted
	}

	// Detect format
	format, err := s.detectFormat(ctx, path, data)
	if err != nil {
		return &ConfigError{
			Type:    ErrorParse,
			Path:    path,
			Message: "failed to detect configuration format",
			Cause:   err,
		}
	}

	// Parse into map for processing
	parsed, err := s.parser.Parse(ctx, data, format)
	if err != nil {
		return &ConfigError{
			Type:    ErrorParse,
			Path:    path,
			Message: fmt.Sprintf("failed to parse %s configuration", format),
			Cause:   err,
		}
	}

	// Apply defaults
	if defaults != nil {
		parsed = s.applyDefaults(parsed, defaults)
	}

	// Convert map to target struct
	if err := s.unmarshalMap(parsed, target); err != nil {
		return &ConfigError{
			Type:    ErrorParse,
			Path:    path,
			Message: "failed to unmarshal configuration",
			Cause:   err,
		}
	}

	// Cache the result
	if s.cache != nil {
		info, _ := s.repository.Stat(ctx, path)
		_ = s.cache.Set(path, CachedConfig{
			Data:     parsed,
			LoadedAt: time.Now(),
			ModTime:  info.ModTime,
			Format:   format,
		})
	}

	s.logger.Info("Configuration loaded successfully",
		zap.String("path", path),
		zap.String("format", string(format)))

	return nil
}

// SaveFile saves configuration from source struct to a file
func (s *service) SaveFile(ctx context.Context, path string, source interface{}, opts SaveOptions) error {
	s.logger.Info("Saving configuration file",
		zap.String("path", path),
		zap.String("format", string(opts.Format)))

	// Convert struct to map
	data := s.structToMap(source)

	// Validate if schema provided
	if opts.Schema != nil {
		if err := s.validator.ValidateSchema(ctx, data, *opts.Schema); err != nil {
			return &ConfigError{
				Type:    ErrorValidation,
				Path:    path,
				Message: "configuration validation failed",
				Cause:   err,
			}
		}
	}

	// Encrypt specific fields if requested
	if s.encryptor != nil && len(opts.EncryptFields) > 0 {
		for _, field := range opts.EncryptFields {
			if err := s.encryptor.EncryptField(ctx, data, field); err != nil {
				return &ConfigError{
					Type:    ErrorEncryption,
					Path:    path,
					Field:   field,
					Message: "failed to encrypt field",
					Cause:   err,
				}
			}
		}
	}

	// Marshal to bytes
	marshaled, err := s.parser.Marshal(ctx, data, opts.Format)
	if err != nil {
		return &ConfigError{
			Type:    ErrorSave,
			Path:    path,
			Message: fmt.Sprintf("failed to marshal %s configuration", opts.Format),
			Cause:   err,
		}
	}

	// Encrypt entire file if requested
	if s.encryptor != nil && opts.Encrypt {
		encrypted, err := s.encryptor.Encrypt(ctx, marshaled)
		if err != nil {
			return &ConfigError{
				Type:    ErrorEncryption,
				Path:    path,
				Message: "failed to encrypt configuration",
				Cause:   err,
			}
		}
		marshaled = encrypted
	}

	// Create backup if requested and file exists
	if opts.Backup {
		exists, _ := s.repository.Exists(ctx, path)
		if exists {
			backupPath := fmt.Sprintf("%s.backup.%d", path, time.Now().Unix())
			if data, err := s.repository.Read(ctx, path); err == nil {
				if err := s.repository.Write(ctx, backupPath, data, opts.Permission); err != nil {
					s.logger.Warn("Failed to create backup",
						zap.String("backup", backupPath),
						zap.Error(err))
				}
				s.logger.Info("Created configuration backup",
					zap.String("backup", backupPath))
			}
		}
	}

	// Write the file
	if err := s.repository.Write(ctx, path, marshaled, opts.Permission); err != nil {
		return &ConfigError{
			Type:    ErrorSave,
			Path:    path,
			Message: "failed to write configuration file",
			Cause:   err,
		}
	}

	// Invalidate cache
	if s.cache != nil {
		_ = s.cache.Delete(path)
	}

	s.logger.Info("Configuration saved successfully",
		zap.String("path", path),
		zap.Int("size", len(marshaled)))

	return nil
}

// Validate validates configuration against a schema
func (s *service) Validate(ctx context.Context, data interface{}, schema Schema) error {
	return s.validator.ValidateSchema(ctx, data, schema)
}

// Watch watches a configuration file for changes
func (s *service) Watch(ctx context.Context, path string, callback WatchCallback) (CancelFunc, error) {
	s.logger.Info("Setting up configuration watch",
		zap.String("path", path))

	// Create watcher
	watcher := &fileWatcher{
		path:       path,
		callback:   callback,
		repository: s.repository,
		parser:     s.parser,
		logger:     s.logger,
		stop:       make(chan struct{}),
		events:     make(chan WatchEvent, 10),
	}

	// Start watching
	if err := watcher.Start(ctx); err != nil {
		return nil, &ConfigError{
			Type:    ErrorWatch,
			Path:    path,
			Message: "failed to start watcher",
			Cause:   err,
		}
	}

	// Track watcher
	s.watchMutex.Lock()
	s.watchers[path] = watcher
	s.watchMutex.Unlock()

	// Return cancel function
	return func() {
		s.watchMutex.Lock()
		delete(s.watchers, path)
		s.watchMutex.Unlock()
		if err := watcher.Stop(); err != nil {
			s.logger.Warn("Failed to stop watcher", 
				zap.String("path", path),
				zap.Error(err))
		}
	}, nil
}

// Get retrieves a single configuration value by key path
func (s *service) Get(ctx context.Context, path string, key string) (interface{}, error) {
	// Load configuration into map
	var data map[string]interface{}
	if err := s.LoadFile(ctx, path, &data); err != nil {
		return nil, err
	}

	// Navigate to the key
	parts := strings.Split(key, ".")
	current := interface{}(data)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		case map[interface{}]interface{}:
			current = v[part]
		default:
			return nil, &ConfigError{
				Type:    ErrorLoad,
				Path:    path,
				Field:   key,
				Message: "key not found",
			}
		}
	}

	return current, nil
}

// Set sets a single configuration value by key path
func (s *service) Set(ctx context.Context, path string, key string, value interface{}) error {
	// Load existing configuration
	var data map[string]interface{}
	if err := s.LoadFile(ctx, path, &data); err != nil {
		// If file doesn't exist, create new config
		if configErr, ok := err.(*ConfigError); ok && configErr.Type == ErrorNotFound {
			data = make(map[string]interface{})
		} else {
			return err
		}
	}

	// Navigate to the key and set value
	parts := strings.Split(key, ".")
	current := interface{}(data)

	for i, part := range parts {
		if i == len(parts)-1 {
			// Set the value
			switch v := current.(type) {
			case map[string]interface{}:
				v[part] = value
			case map[interface{}]interface{}:
				v[part] = value
			default:
				return &ConfigError{
					Type:    ErrorSave,
					Path:    path,
					Field:   key,
					Message: "cannot set value on non-map type",
				}
			}
		} else {
			// Navigate deeper
			switch v := current.(type) {
			case map[string]interface{}:
				if _, ok := v[part]; !ok {
					v[part] = make(map[string]interface{})
				}
				current = v[part]
			case map[interface{}]interface{}:
				if _, ok := v[part]; !ok {
					v[part] = make(map[string]interface{})
				}
				current = v[part]
			default:
				return &ConfigError{
					Type:    ErrorSave,
					Path:    path,
					Field:   key,
					Message: "cannot navigate through non-map type",
				}
			}
		}
	}

	// Save the updated configuration
	return s.SaveFile(ctx, path, data, DefaultSaveOptions())
}

// Helper methods

// detectFormat detects the configuration format
func (s *service) detectFormat(ctx context.Context, path string, data []byte) (Format, error) {
	// Try to detect from file extension
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return FormatJSON, nil
	case ".yaml", ".yml":
		return FormatYAML, nil
	case ".toml":
		return FormatTOML, nil
	case ".ini":
		return FormatINI, nil
	case ".env":
		return FormatENV, nil
	case ".hcl":
		return FormatHCL, nil
	}

	// Try to detect from content
	return s.parser.DetectFormat(ctx, data, path)
}

// applyDefaults merges defaults into the configuration
func (s *service) applyDefaults(config, defaults map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// Copy defaults
	for k, v := range defaults {
		result[k] = v
	}

	// Override with actual config
	for k, v := range config {
		result[k] = v
	}

	return result
}

// structToMap converts a struct to a map
func (s *service) structToMap(v interface{}) map[string]interface{} {
	// Use JSON as intermediate format for simplicity
	data, _ := json.Marshal(v)
	var result map[string]interface{}
	_ = json.Unmarshal(data, &result)
	return result
}

// unmarshalMap converts a map to a struct
func (s *service) unmarshalMap(data map[string]interface{}, target interface{}) error {
	// Use JSON as intermediate format for simplicity
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(jsonData, target)
}

// unmarshalInto unmarshals cached data into target
func (s *service) unmarshalInto(data interface{}, target interface{}) error {
	if m, ok := data.(map[string]interface{}); ok {
		return s.unmarshalMap(m, target)
	}

	// Use reflection for direct assignment if types match
	targetValue := reflect.ValueOf(target)
	if targetValue.Kind() != reflect.Ptr {
		return fmt.Errorf("target must be a pointer")
	}

	dataValue := reflect.ValueOf(data)
	if targetValue.Elem().Type() == dataValue.Type() {
		targetValue.Elem().Set(dataValue)
		return nil
	}

	return fmt.Errorf("cannot unmarshal %T into %T", data, target)
}

// fileWatcher implements configuration file watching
type fileWatcher struct {
	path       string
	callback   WatchCallback
	repository Repository
	parser     Parser
	logger     *zap.Logger
	stop       chan struct{}
	events     chan WatchEvent
}

// Start starts the file watcher
func (w *fileWatcher) Start(ctx context.Context) error {
	// This is a simplified implementation
	// In a real implementation, you'd use fsnotify or similar
	w.logger.Info("File watcher started", zap.String("path", w.path))
	
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-w.stop:
				return
			case <-ticker.C:
				// Check for file changes (simplified)
				// In a real implementation, use proper file system events
			}
		}
	}()
	
	return nil
}

// Stop stops the file watcher
func (w *fileWatcher) Stop() error {
	close(w.stop)
	close(w.events)
	return nil
}

// Events returns the event channel
func (w *fileWatcher) Events() <-chan WatchEvent {
	return w.events
}
