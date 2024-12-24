package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Database struct {
		Name      string   `yaml:"name"`
		User      string   `yaml:"user"`
		Host      string   `yaml:"host"`
		Port      string   `yaml:"port"`
		Version   string   `yaml:"version"`
		SocketDir string   `yaml:"socketDir"`
		Tables    []string `yaml:"tables"`
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

	// Connection string
	connStr := fmt.Sprintf("host=%s dbname=%s user=%s port=%s sslmode=disable", config.Database.SocketDir, config.Database.Name, config.Database.User, config.Database.Port)

	// Open a connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to open a connection: %v", err)
	}
	defer db.Close()

	// Test the connection
	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	fmt.Println("Successfully connected to PostgreSQL over UNIX socket!")

	// Insert a test log entry into the 'logs' table
	insertQuery := "INSERT INTO logs (timestamp, level, message) VALUES ($1, $2, $3)"
	_, err = db.Exec(insertQuery, time.Now(), config.Logging.Level, "Test log entry")
	if err != nil {
		log.Fatalf("Failed to insert log entry: %v", err)
	}

	fmt.Println("Test log entry inserted successfully!")

	// Verify the insertion by querying the latest log
	var timestamp time.Time
	var level, message string
	query := "SELECT timestamp, level, message FROM logs ORDER BY timestamp DESC LIMIT 1"
	err = db.QueryRow(query).Scan(&timestamp, &level, &message)
	if err != nil {
		log.Fatalf("Failed to query the latest log entry: %v", err)
	}

	fmt.Printf("Latest log entry:\nTimestamp: %s\nLevel: %s\nMessage: %s\n", timestamp, level, message)
}
