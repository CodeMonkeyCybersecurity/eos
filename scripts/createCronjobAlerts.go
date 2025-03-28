package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// getCrontab retrieves the current user's crontab.
func getCrontab() (string, error) {
	cmd := exec.Command("crontab", "-l")
	var out bytes.Buffer
	cmd.Stdout = &out
	// If there is no crontab, crontab -l returns an error. We'll treat it as an empty crontab.
	err := cmd.Run()
	if err != nil {
		return "", nil
	}
	return out.String(), nil
}

// backupCrontab creates a timestamped backup of the current crontab.
func backupCrontab(crontab string) error {
	timestamp := time.Now().Format("20060102-150405")
	backupFile := fmt.Sprintf("crontab.backup.%s", timestamp)
	fmt.Printf("Backing up current crontab to %s...\n", backupFile)
	return ioutil.WriteFile(backupFile, []byte(crontab), 0644)
}

// setCrontab writes the provided content to the crontab.
func setCrontab(crontab string) error {
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(crontab)
	return cmd.Run()
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter email address for cronjob failure alerts: ")
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)
	if email == "" {
		log.Fatal("No email address provided, aborting.")
	}

	// Retrieve current crontab.
	currentCrontab, err := getCrontab()
	if err != nil {
		log.Fatalf("Error retrieving current crontab: %v", err)
	}

	// Backup current crontab.
	if err := backupCrontab(currentCrontab); err != nil {
		log.Printf("Warning: could not backup current crontab: %v", err)
	} else {
		fmt.Println("Crontab backup complete.")
	}

	// Process current crontab, updating or inserting the MAILTO variable.
	lines := strings.Split(currentCrontab, "\n")
	mailtoSet := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "MAILTO=") {
			lines[i] = "MAILTO=" + email
			mailtoSet = true
			break
		}
	}
	if !mailtoSet {
		// Prepend the MAILTO setting if it doesn't exist.
		lines = append([]string{"MAILTO=" + email}, lines...)
	}

	newCrontab := strings.Join(lines, "\n")

	// Update the crontab.
	if err := setCrontab(newCrontab); err != nil {
		log.Fatalf("Failed to update crontab: %v", err)
	}
	fmt.Println("Crontab successfully updated to send email alerts on failed cronjobs.")

	// Display the new crontab for verification.
	fmt.Println("\nNew crontab content:")
	fmt.Println("====================================")
	fmt.Println(newCrontab)
	fmt.Println("====================================")
}
