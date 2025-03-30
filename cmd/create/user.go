package create

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

// createUserCmd represents the command for creating a single user
var CreateUserCmd = &cobra.Command{
	Use:   "user",
	Short: "Create a new user",
	Long:  `Create a new user account interactively in the system.`,
	Run: func(cmd *cobra.Command, args []string) {
		CreateUser() // Call the interactive function
	},
}

// CreateUser handles the creation of a new user interactively
func CreateUser() {
	// Handle interrupt signals (Ctrl+C)
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChan
		fmt.Println("\nOperation canceled. Exiting...")
		os.Exit(1)
	}()

	// Ensure the script is run as root
	if os.Getenv("SUDO_USER") == "" && os.Geteuid() != 0 {
		fmt.Println("Please run as root or with sudo")
		return
	}

	reader := bufio.NewReader(os.Stdin)

	// Prompt for new username
	fmt.Print("Enter the new username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	// Check if the username is not empty
	if username == "" {
		fmt.Println("Username cannot be empty!")
		return
	}

	// Check if user already exists
	_, err := exec.Command("id", username).Output()
	if err == nil {
		fmt.Printf("User %s already exists!\n", username)
		return
	}

	// Prompt for password
	fmt.Print("Enter the password: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	// Confirm password
	fmt.Print("Confirm password: ")
	password2, _ := reader.ReadString('\n')
	password2 = strings.TrimSpace(password2)

	// Check if passwords match
	if password != password2 {
		fmt.Println("Passwords do not match!")
		return
	}

	// Add user
	err = exec.Command("useradd", "-m", "-s", "/bin/bash", username).Run()
	if err != nil {
		fmt.Printf("Error creating user: %v\n", err)
		return
	}

	// Set the user password
	passCmd := fmt.Sprintf("echo %s:%s | chpasswd", username, password)
	err = exec.Command("sh", "-c", passCmd).Run()
	if err != nil {
		fmt.Printf("Error setting password for user: %v\n", err)
		return
	}

	// Ask for sudo privileges
	fmt.Print("Should this user have sudo privileges? (yes/no): ")
	grantsudo, _ := reader.ReadString('\n')
	grantsudo = strings.TrimSpace(strings.ToLower(grantsudo))

	if grantsudo == "yes" {
		err = exec.Command("usermod", "-aG", "sudo", username).Run()
		if err != nil {
			fmt.Printf("Error granting sudo privileges: %v\n", err)
			return
		}
		fmt.Printf("User %s has been granted sudo privileges.\n", username)
	}

	fmt.Printf("User %s created successfully.\n", username)
}

func init() {
	// Register the create user command with the create command
	CreateCmd.AddCommand(CreateUserCmd)
}
