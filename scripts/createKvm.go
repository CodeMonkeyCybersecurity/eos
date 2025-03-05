package main

import (
    "fmt"
    "log"
    "os"
    "os/exec"
)

// isCommandAvailable checks if a given command (e.g. "apt-get") is in the system's PATH
func isCommandAvailable(name string) bool {
    _, err := exec.LookPath(name)
    return err == nil
}

func main() {
    // Check for APT (Debian/Ubuntu)
    if isCommandAvailable("apt-get") {
        fmt.Println("Detected Debian/Ubuntu. Installing KVM packages...")
        // The commands you want to run:
        //  1. sudo apt-get update
        //  2. sudo apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients \
        //     bridge-utils virt-manager virt-viewer
        installCmd := exec.Command("bash", "-c", 
            "sudo apt-get update && " +
            "sudo apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager virt-viewer")
        installCmd.Stdout = os.Stdout
        installCmd.Stderr = os.Stderr

        if err := installCmd.Run(); err != nil {
            log.Fatalf("Error installing KVM on Debian/Ubuntu: %v", err)
        }
        fmt.Println("KVM and dependencies installed successfully on Debian/Ubuntu!")

    // Check for DNF (Fedora, newer CentOS, RHEL)
    } else if isCommandAvailable("dnf") {
        fmt.Println("Detected Fedora/CentOS (DNF). Installing KVM packages...")
        installCmd := exec.Command("bash", "-c",
            "sudo dnf install -y qemu-kvm libvirt libvirt-devel virt-install bridge-utils virt-viewer")
        installCmd.Stdout = os.Stdout
        installCmd.Stderr = os.Stderr

        if err := installCmd.Run(); err != nil {
            log.Fatalf("Error installing KVM on Fedora/CentOS (DNF): %v", err)
        }
        fmt.Println("KVM and dependencies installed successfully on Fedora/CentOS (DNF)!")

    // Check for YUM (older CentOS/RHEL)
    } else if isCommandAvailable("yum") {
        fmt.Println("Detected CentOS/RHEL (YUM). Installing KVM packages...")
        installCmd := exec.Command("bash", "-c",
            "sudo yum install -y qemu-kvm libvirt libvirt-devel virt-install bridge-utils virt-viewer")
        installCmd.Stdout = os.Stdout
        installCmd.Stderr = os.Stderr

        if err := installCmd.Run(); err != nil {
            log.Fatalf("Error installing KVM on CentOS/RHEL (YUM): %v", err)
        }
        fmt.Println("KVM and dependencies installed successfully on CentOS/RHEL (YUM)!")

    } else {
        fmt.Println("Could not detect a supported package manager (apt-get, dnf, yum).")
        fmt.Println("Please install KVM, libvirt, and virt-viewer manually.")
    }
}
