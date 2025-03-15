package utils

import (
	"log"
	"os"
)

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
