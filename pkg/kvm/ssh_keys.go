// pkg/kvm/ssh_key.go

package kvm

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/templates"
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

func GenerateKickstartWithSSH(vmName, pubkeyPath string) (string, error) {
	key, err := os.ReadFile(pubkeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read SSH key: %w", err)
	}

	tmpl, err := template.New("kickstart").Parse(templates.KickstartTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, TemplateContext{
		SSHKey:   strings.TrimSpace(string(key)),
		VMName:   vmName,
		Hostname: vmName,
	})
	if err != nil {
		return "", fmt.Errorf("failed to render kickstart: %w", err)
	}

	tempPath := filepath.Join(os.TempDir(), vmName+"-kickstart.ks")
	if err := os.WriteFile(tempPath, buf.Bytes(), 0644); err != nil {
		return "", err
	}
	return tempPath, nil
}
