// pkg/utils/detach.go
package utils

import (
	"fmt"
	"time"
)

// DetachAfterDelay prints a message and detaches the terminal after N seconds.
func DetachAfterDelay(seconds int, serviceName string) {
	fmt.Printf(" Waiting %d seconds for %s to start...\n", seconds, serviceName)
	time.Sleep(time.Duration(seconds) * time.Second)
	fmt.Println(" Detaching from logs. Vault should now be running in the background.")
}
