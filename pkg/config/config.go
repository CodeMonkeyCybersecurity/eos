//pkg/config/config.go

package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// Config is the global viper instance (use sparingly for tests!).
var Config = viper.New()

// LoadConfig loads a config file from disk (YAML, TOML, JSON supported by Viper).
func LoadConfig(path string) error {
	Config.SetConfigFile(path)
	if err := Config.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}
	return nil
}

// MustLoadConfig is like LoadConfig, but panics on error (for one-liners/main).
func MustLoadConfig(path string) {
	if err := LoadConfig(path); err != nil {
		panic(err)
	}
}

// LoadWithDefaults loads config from file, then overlays any defaults provided.
// Defaults take effect only if not present in file or env.
func LoadWithDefaults(path string, defaults map[string]interface{}) error {
	for k, v := range defaults {
		Config.SetDefault(k, v)
	}
	return LoadConfig(path)
}

// BindEnv binds an environment variable override for a config key.
func BindEnv(key, envVar string) error {
	return Config.BindEnv(key, envVar)
}

// BindEnvs is a batch helper for BindEnv.
func BindEnvs(bindings map[string]string) error {
	for key, envVar := range bindings {
		if err := BindEnv(key, envVar); err != nil {
			return err
		}
	}
	return nil
}

// Require checks that the given key exists and is non-empty.
func Require(key string) error {
	if !Config.IsSet(key) || Config.Get(key) == "" {
		return fmt.Errorf("required config key missing: %s", key)
	}
	return nil
}

// MustRequire panics if Require fails.
func MustRequire(key string) {
	if err := Require(key); err != nil {
		panic(err)
	}
}

// GetString is a handy type-safe getter with required-check.
func GetString(key string, required bool) string {
	val := Config.GetString(key)
	if required && val == "" {
		panic(fmt.Sprintf("required config key missing or empty: %s", key))
	}
	return val
}

// GetDuration parses a key as time.Duration (with default fallback).
func GetDuration(key string, fallback time.Duration) time.Duration {
	s := Config.GetString(key)
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

// Reload will re-read the config from disk (if changed), returns error if failed.
func Reload() error {
	return Config.ReadInConfig()
}

// WatchAndHotReload calls fn() on any config file change (background goroutine).
// (Returns the cleanup function for stopping the watcher.)
func WatchAndHotReload(fn func()) (func(), error) {
	Config.WatchConfig()
	Config.OnConfigChange(func(e fsnotify.Event) {
		fn()
	})
	return func() { Config.OnConfigChange(nil) }, nil
}

// SetDefaultEnvPrefix sets a prefix for environment variables (e.g., "EOS_").
func SetDefaultEnvPrefix(prefix string) {
	Config.SetEnvPrefix(prefix)
	Config.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	Config.AutomaticEnv()
}
