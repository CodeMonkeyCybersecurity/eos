package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	// Define the connection parameters
	// Replace "<dbname>" and "<username>" with your PostgreSQL database and user.
	socketDir := "/var/run/postgresql"
	database := "eos_db"
	user := "eos_user"

	// Connection string
	connStr := fmt.Sprintf("host=%s dbname=%s user=%s sslmode=disable", socketDir, database, user)

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

	// Example query
	query := "SELECT current_date"
	var currentDate string
	err = db.QueryRow(query).Scan(&currentDate)
	if err != nil {
		log.Fatalf("Query failed: %v", err)
	}

	fmt.Printf("Current date from PostgreSQL: %s\n", currentDate)
}
