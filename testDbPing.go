package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	// Connection details
	host := "localhost"
	port := "5432"
	user := "eos_user"
	dbname := "eos_db"

	// Connection string (no password for peer authentication)
	connStr := fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=disable", host, port, user, dbname)

	// Open a connection to the database
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to open database connection: %v", err)
	}
	defer db.Close()

	// Ping the database to check readiness
	if err := db.Ping(); err != nil {
		log.Fatalf("Database is not ready: %v", err)
	}

	fmt.Println("Database is ready!")
}
