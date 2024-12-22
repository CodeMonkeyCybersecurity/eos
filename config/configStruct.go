package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type DatabaseConfig struct {
	Name    string `yaml:"name"`
	User    string `yaml:"user"`
	Host    string `yaml:"host"`
	Port    string `yaml:"port"`
	Version string `yaml:"version"`
}

type Config struct {
	Database DatabaseConfig `yaml:"database"`
}

func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	config := &Config{}
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(config); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %w", err)
	}

	return config, nil
}
