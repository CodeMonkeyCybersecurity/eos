package main

import (
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the structure of the YAML configuration file
type Config struct {
	Database struct {
		Name    string `yaml:"name"`
		User    string `yaml:"user"`
		Host    string `yaml:"host"`
		Port    string `yaml:"port"`
		Version string `yaml:"version"`
	} `yaml:"database"`
	Logging struct {
		Level string `yaml:"level"`
		File  string `yaml:"file"`
	} `yaml:"logging"`
}

func main() {
	// Specify the path to your YAML file
	yamlFilePath := "config/default.yaml"

	// Read the YAML file
	file, err := os.ReadFile(yamlFilePath)
	if err != nil {
		log.Fatalf("Error reading YAML file: %v\n", err)
	}

	// Parse the YAML content into the Config struct
	var config Config
	err = yaml.Unmarshal(file, &config)
	if err != nil {
		log.Fatalf("Error parsing YAML file: %v\n", err)
	}

	// Access and print values from the parsed config
	fmt.Printf("Database Name: %s\n", config.Database.Name)
	fmt.Printf("Database User: %s\n", config.Database.User)
	fmt.Printf("Database Host: %s\n", config.Database.Host)
	fmt.Printf("Database Port: %s\n", config.Database.Port)
	fmt.Printf("Database Version: %s\n", config.Database.Version)
	fmt.Printf("Log Level: %s\n", config.Logging.Level)
	fmt.Printf("Log File: %s\n", config.Logging.File)
}
