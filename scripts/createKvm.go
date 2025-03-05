package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// isCommandAvailable checks if a given command (e.g. "apt-get") is in the system's PATH.
func isCommandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// setACLForDirectory grants the libvirt-qemu user read and execute permissions on the given directory recursively.
func setACLForDirectory(dir string) {
	fmt.Printf("Adjusting ACLs for directory %s recursively...\n", dir)
	cmd := exec.Command("setfacl", "-R", "-m", "u:libvirt-qemu:rx", dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("Warning: could not set ACL on %s: %v\n", dir, err)
	} else {
		fmt.Printf("ACL set successfully on %s.\n", dir)
	}
}

// setDefaultNetworkAutostart starts the default libvirt network and sets it to autostart.
func setDefaultNetworkAutostart() {
	fmt.Println("Starting the default libvirt network...")
	startCmd := exec.Command("virsh", "net-start", "default")
	startCmd.Stdout = os.Stdout
	startCmd.Stderr = os.Stderr
	if err := startCmd.Run(); err != nil {
		fmt.Printf("Error starting default network: %v\n", err)
	} else {
		fmt.Println("Default network started successfully.")
	}

	fmt.Println("Setting the default libvirt network to autostart...")
	autostartCmd := exec.Command("virsh", "net-autostart", "default")
	autostartCmd.Stdout = os.Stdout
	autostartCmd.Stderr = os.Stderr
	if err := autostartCmd.Run(); err != nil {
		fmt.Printf("Error setting default network to autostart: %v\n", err)
	} else {
		fmt.Println("Default network set to autostart successfully.")
	}
}

func main() {
	// Ensure the script is run as root.
	if os.Geteuid() != 0 {
		fmt.Println("This script must be run as root.")
		os.Exit(1)
	}

	// Install KVM packages based on available package manager.
	if isCommandAvailable("apt-get") {
		fmt.Println("Detected Debian/Ubuntu. Installing KVM packages...")
		installCmd := exec.Command("bash", "-c",
			"apt-get update && "+
				"apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager virt-viewer")
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr

		if err := installCmd.Run(); err != nil {
			log.Fatalf("Error installing KVM on Debian/Ubuntu: %v", err)
		}
		fmt.Println("KVM and dependencies installed successfully on Debian/Ubuntu!")

	} else if isCommandAvailable("dnf") {
		fmt.Println("Detected Fedora/CentOS (DNF). Installing KVM packages...")
		installCmd := exec.Command("bash", "-c",
			"dnf install -y qemu-kvm libvirt libvirt-devel virt-install bridge-utils virt-viewer")
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr

		if err := installCmd.Run(); err != nil {
			log.Fatalf("Error installing KVM on Fedora/CentOS (DNF): %v", err)
		}
		fmt.Println("KVM and dependencies installed successfully on Fedora/CentOS (DNF)!")

	} else if isCommandAvailable("yum") {
		fmt.Println("Detected CentOS/RHEL (YUM). Installing KVM packages...")
		installCmd := exec.Command("bash", "-c",
			"yum install -y qemu-kvm libvirt libvirt-devel virt-install bridge-utils virt-viewer")
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr

		if err := installCmd.Run(); err != nil {
			log.Fatalf("Error installing KVM on CentOS/RHEL (YUM): %v", err)
		}
		fmt.Println("KVM and dependencies installed successfully on CentOS/RHEL (YUM)!")
	} else {
		fmt.Println("Could not detect a supported package manager (apt-get, dnf, yum).")
		fmt.Println("Please install KVM, libvirt, and virt-viewer manually.")
		os.Exit(1)
	}

	// Ask the user if they'd like to grant libvirt access to a directory for ISO files.
	reader := bufio.NewReader(os.Stdin)
	defaultDir := "/mnt/iso"
	fmt.Printf("\nThe hypervisor (libvirt-qemu) needs access to at least one directory where your ISO files are stored.\n")
	fmt.Printf("The default directory is '%s'. Do you want to use this directory? [Y/n]: ", defaultDir)
	answer, err := reader.ReadString('\n')
	if err != nil {
	    log.Fatalf("Error reading input: %v", err)
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	
	var dirToUse string
	if answer == "" || answer == "y" || answer == "yes" {
	    dirToUse = defaultDir
	} else {
	    fmt.Print("Please enter the full path of the directory containing your ISO files: ")
	    dirInput, err := reader.ReadString('\n')
	    if err != nil {
	        log.Fatalf("Error reading directory path: %v", err)
	    }
	    dirToUse = strings.TrimSpace(dirInput)
	}
	
	// Check if the directory exists.
	info, err := os.Stat(dirToUse)
	if err != nil || !info.IsDir() {
	    fmt.Printf("Directory %s not found or is not a directory; skipping ACL adjustment.\n", dirToUse)
	} else {
	    // Set ACL on the specified directory recursively.
	    setACLForDirectory(dirToUse)
	}
	

	// Ask the user if they'd like to start and autostart the default libvirt network.
	fmt.Println("\nKVM requires at least one network to be active before you install/start virtual machines.")
	fmt.Print("Would you like to start and set the default network to autostart? [y/N]: ")
	netAnswer, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("Error reading input: %v", err)
	}
	netAnswer = strings.TrimSpace(strings.ToLower(netAnswer))
	if netAnswer == "y" || netAnswer == "yes" {
		setDefaultNetworkAutostart()
	} else {
		fmt.Println("Skipping network autostart. You will need to start the default network manually if required with something similar to 'virsh net-start default'.")
	}
}
