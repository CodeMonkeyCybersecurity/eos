package utils

import (
	"log"
	"fmt"
	"os"
	"os/exec"

	"gopkg.in/yaml.v3"
)


//
//---------------------------- HOSTNAME ---------------------------- //
//

// GetInternalHostname returns the machine's hostname.
// If os.Hostname() fails, it logs the error and returns "localhost".
func GetInternalHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Unable to retrieve hostname, defaulting to localhost: %v", err)
		return "localhost"
	}
	return hostname
}


//
//---------------------------- ERROR HANDLING ---------------------------- //
//

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


//
//---------------------------- PERMISSIONS ---------------------------- //
//

// CheckSudo checks if the current user has sudo privileges
func CheckSudo() bool {
	cmd := exec.Command("sudo", "-n", "true") // Non-interactive sudo check
	err := cmd.Run()
	return err == nil
}


//
//---------------------------- YAML ---------------------------- //
//


// Recursive function to process and print nested YAML structures
func processMap(data map[string]interface{}, indent string) {
	for key, value := range data {
		switch v := value.(type) {
		case map[string]interface{}:
			// If the value is a nested map, call processMap recursively
			fmt.Printf("%s%s:\n", indent, key)
			processMap(v, indent+"  ")
		case []interface{}:
			// If the value is a slice, process each element
			fmt.Printf("%s%s:\n", indent, key)
			for _, item := range v {
				if itemMap, ok := item.(map[string]interface{}); ok {
					processMap(itemMap, indent+"  ")
				} else {
					fmt.Printf("%s  - %v\n", indent, item)
				}
			}
		default:
			// Print scalar values
			fmt.Printf("%s%s: %v\n", indent, key, v)
		}
	}
}
