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

// setACLForDirectory grants the libvirt-qemu user read and execute permissions on the given directory.
func setACLForDirectory(dir string) {
    fmt.Printf("Adjusting ACLs for directory %s...\n", dir)
    cmd := exec.Command("setfacl", "-m", "u:libvirt-qemu:rx", dir)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    if err := cmd.Run(); err != nil {
        fmt.Printf("Warning: could not set ACL on %s: %v\n", dir, err)
    } else {
        fmt.Printf("ACL set successfully on %s.\n", dir)
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
            "apt-get update && " +
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
    fmt.Println("\nThe hypervisor (libvirt-qemu) needs access to at least one directory where your ISO files are stored.")
    fmt.Print("Would you like to grant access via ACLs? [y/N]: ")
    answer, err := reader.ReadString('\n')
    if err != nil {
        log.Fatalf("Error reading input: %v", err)
    }
    answer = strings.TrimSpace(strings.ToLower(answer))
    if answer == "y" || answer == "yes" {
        fmt.Print("Please enter the full path of the directory containing your ISO files: ")
        dirInput, err := reader.ReadString('\n')
        if err != nil {
            log.Fatalf("Error reading directory path: %v", err)
        }
        dirInput = strings.TrimSpace(dirInput)
        // Check if directory exists.
        info, err := os.Stat(dirInput)
        if err != nil || !info.IsDir() {
            fmt.Printf("Directory %s not found or is not a directory; skipping ACL adjustment.\n", dirInput)
        } else {
            // Set ACL on the specified directory.
            setACLForDirectory(dirInput)
        }
    } else {
        fmt.Println("Skipping ACL adjustment. Make sure the hypervisor can access your ISO files.")
    }
}
