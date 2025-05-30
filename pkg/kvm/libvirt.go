// pkg/kvm/libvirt.go

package kvm

import (
	"fmt"
	"os"
	"os/exec"
)

func SetLibvirtACL(dir string) {
	fmt.Println("Setting libvirt ACL on directory:", dir)
	cmd := exec.Command("setfacl", "-R", "-m", "u:libvirt-qemu:rx", dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

func SetLibvirtDefaultNetworkAutostart() {
	fmt.Println("Starting and autostarting default libvirt network...")
	_ = exec.Command("virsh", "net-start", "default").Run()
	_ = exec.Command("virsh", "net-autostart", "default").Run()
}
