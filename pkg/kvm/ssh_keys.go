// pkg/kvm/ssh_key.go

package kvm

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

func PrepareTenantSSHKey(vmName string) (string, string, error) {
	privTemp, pubTemp, err := GenerateSSHKeyPair(vmName)
	if err != nil {
		return "", "", err
	}

	destKey := filepath.Join("/var/lib/eos/ssh_keys", vmName+".key")
	if err := os.MkdirAll(filepath.Dir(destKey), 0700); err != nil {
		return "", "", fmt.Errorf("failed to create key dir: %w", err)
	}
	if err := os.Rename(privTemp, destKey); err != nil {
		return "", "", fmt.Errorf("failed to move private key: %w", err)
	}
	if err := os.Chmod(destKey, 0600); err != nil {
		return "", "", fmt.Errorf("chmod failed: %w", err)
	}

	return pubTemp, destKey, nil
}

func GenerateSSHKeyPair(vmName string) (pubPath, privPath string, err error) {
	keyDir := filepath.Join("/tmp", "ssh_keys")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return "", "", fmt.Errorf("mkdir failed: %w", err)
	}

	privPath = filepath.Join(keyDir, vmName+".key")
	pubPath = privPath + ".pub"

	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", privPath, "-C", vmName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("ssh-keygen failed: %v\n%s", err, string(out))
	}

	return pubPath, privPath, nil
}

// GenerateEd25519Keys generates ed25519 SSH key pair in specified directory
func GenerateEd25519Keys(sshDir string) (publicKeyPath, privateKeyPath string, err error) {
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return "", "", fmt.Errorf("failed to create SSH directory: %w", err)
	}

	privateKeyPath = filepath.Join(sshDir, "id_ed25519")
	publicKeyPath = privateKeyPath + ".pub"

	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", privateKeyPath, "-C", "eos-vm")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("ssh-keygen failed: %v\n%s", err, string(out))
	}

	return publicKeyPath, privateKeyPath, nil
}

func GenerateKickstartWithSSH(vmName, pubkeyPath string) (string, error) {
	key, err := os.ReadFile(pubkeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read SSH key: %w", err)
	}

	ctx := TemplateContext{
		SSHKey:   strings.TrimSpace(string(key)),
		VMName:   vmName,
		Username: "debugadmin",
		Password: "changeme123", // or generated
		Hostname: vmName,
		// TailscaleKey: "...", // optional
	}

	if err := ctx.Validate(); err != nil {
		return "", fmt.Errorf("invalid template context: %w", err)
	}

	tmpl, err := template.New("kickstart").Parse(KickstartTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return "", fmt.Errorf("failed to render kickstart: %w", err)
	}

	tempPath := filepath.Join(os.TempDir(), vmName+"-kickstart.ks")
	if err := os.WriteFile(tempPath, buf.Bytes(), 0644); err != nil {
		return "", err
	}

	return tempPath, nil
}
