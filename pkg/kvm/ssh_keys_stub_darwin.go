//go:build darwin
// +build darwin

// pkg/kvm/ssh_keys_stub_darwin.go
// macOS stub for SSH key management

package kvm

import "fmt"

// PrepareTenantSSHKey stub
func PrepareTenantSSHKey(vmName string) (string, string, error) {
	return "", "", fmt.Errorf(errLibvirtMacOS)
}

// GenerateSSHKeyPair stub
func GenerateSSHKeyPair(vmName string) (pubPath, privPath string, err error) {
	return "", "", fmt.Errorf(errLibvirtMacOS)
}

// GenerateEd25519Keys stub
func GenerateEd25519Keys(sshDir string) (publicKeyPath, privateKeyPath string, err error) {
	return "", "", fmt.Errorf(errLibvirtMacOS)
}

// GenerateKickstartWithSSH stub
func GenerateKickstartWithSSH(vmName, pubkeyPath string) (string, error) {
	return "", fmt.Errorf(errLibvirtMacOS)
}
