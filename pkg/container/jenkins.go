// pkg/docker/jenkins.go
package container

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/templates"
	vaultapi "github.com/hashicorp/vault/api"
)

// JenkinsOptions holds all of the template variables our Jenkins template expects.
type JenkinsOptions struct {
	JenkinsImage      string
	JenkinsContainer  string
	JenkinsUIPort     string
	JenkinsAgentPort  string
	VolumeName        string
	NetworkName       string
	SSHAgentContainer string
	SSHAgentImage     string
}

// WriteAndUpJenkins will:
//  1. Render the JenkinsComposeTemplate into /opt/<app>/docker-compose.yml
//  2. Call ComposeUpInDir("/opt/<app>") to bring it up detached.
//
// If you want to deploy under /opt/jenkins, simply use appName="jenkins".
func WriteAndUpJenkins(rc *eos_io.RuntimeContext, appName string, opts JenkinsOptions) error {
	// 1) make sure /opt/<appName> exists
	dir := filepath.Join("/opt", appName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// 2) render template to bytes
	var buf bytes.Buffer
	if err := templates.JenkinsComposeTemplate.Execute(&buf, opts); err != nil {
		return fmt.Errorf("render jenkins compose template: %w", err)
	}

	// 3) write the file
	target := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(target, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write compose file: %w", err)
	}

	// 4) use your existing ComposeUpInDir
	return ComposeUpInDir(rc, dir)
}

// StoreJenkinsAdminPassword writes the Jenkins initial admin password into Vault KV-v2.
//
// It uses the default "secret" mount and writes under the path "jenkins" with
// a field "initialAdminPassword".  That makes the secret readable at:
//
//	vault kv get secret/jenkins
func StoreJenkinsAdminPassword(rc *eos_io.RuntimeContext, client *vaultapi.Client, password string) error {
	// mountPath is the KV-v2 mount (EOS default is "secret")
	kv := client.KVv2("secret")

	// path under the mount.  We'll store all Jenkins data here.
	secretPath := "jenkins"

	data := map[string]interface{}{
		"initialAdminPassword": password,
	}

	if _, err := kv.Put(rc.Ctx, secretPath, data); err != nil {
		return fmt.Errorf("failed to store Jenkins admin password in Vault: %w", err)
	}

	return nil
}
