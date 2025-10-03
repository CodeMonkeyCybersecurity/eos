// pkg/kvm/utils.go
// Utility functions available in all builds (no build tags)

package kvm

import (
	"fmt"
	"os"
	"os/exec"
)

// SetLibvirtACL sets ACL permissions for libvirt on a directory
func SetLibvirtACL(dir string) {
	fmt.Println("Setting libvirt ACL on directory:", dir)
	cmd := exec.Command("setfacl", "-R", "-m", "u:libvirt-qemu:rx", dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}
