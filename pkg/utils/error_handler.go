// /pkg/utils/error_handler.go
package utils

import (
	"fmt"
	"log"
	"os"
)

// HandleError logs an error and optionally exits the program
func HandleError(err error, message string, exit bool) {
	if err != nil {
		log.Printf("[ERROR] %s: %v\n", message, err)
		if exit {
			fmt.Println("Exiting program due to error.")
			os.Exit(1)
		}
	}
}

// WithErrorHandling wraps a function with error handling
func WithErrorHandling(fn func() error) {
	err := fn()
	if err != nil {
		HandleError(err, "An error occurred", true)
	}
}
