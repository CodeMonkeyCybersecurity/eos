package main

import (
	"fmt"
	"log"
	"os/exec"
)

func main() {
	// Execute the systemctl mask command with sudo privileges
	cmd := exec.Command("sudo", "systemctl", "mask", "sleep.target", "suspend.target", "hibernate.target", "hybrid-sleep.target")
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error masking targets: %v", err)
	}
	
	// Print "finis" to indicate the end of the process
	fmt.Println("finis")
}
