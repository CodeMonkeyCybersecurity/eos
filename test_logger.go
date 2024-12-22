package main

import (
	"database/sql"
	"log"

	"your_project_path/pkg/utils" // Replace with the actual path to your utils package

	_ "github.com/lib/pq" // PostgreSQL driver
)

func main() {
	// PostgreSQL connection details
	connStr := "host=localhost port=5432 user=eos_user dbname=eos_db sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}
	defer db.Close()

	// Initialize the logger
	logFilePath := "/tmp/test_logger.log"
	err = utils.InitializeLogger(db, logFilePath, utils.InfoLevel, true)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Retrieve the logger instance
	logger := utils.GetLogger()

	// Test logging different levels
	logger.Debug("This is a DEBUG message")
	logger.Info("This is an INFO message")
	logger.Warn("This is a WARN message")
	logger.Error("This is an ERROR message")
	logger.Critical("This is a CRITICAL message")
	logger.Fatal("This is a FATAL message") // This will terminate the application

	log.Println("Test completed.")
}
