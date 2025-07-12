package cephfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// GenerateSaltStackConfig generates SaltStack configuration for CephFS deployment
func GenerateSaltStackConfig(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if SaltStack is available and prerequisites are met
	logger.Info("Assessing SaltStack prerequisites for CephFS deployment")
	if err := assessSaltStackPrerequisites(rc); err != nil {
		return fmt.Errorf("failed to assess SaltStack prerequisites: %w", err)
	}

	// INTERVENE: Generate SaltStack configuration
	logger.Info("Generating SaltStack configuration for CephFS")
	if err := generateSaltStackConfiguration(rc, config); err != nil {
		return fmt.Errorf("failed to generate SaltStack configuration: %w", err)
	}

	// EVALUATE: Verify configuration was generated correctly
	logger.Info("Verifying SaltStack configuration generation")
	if err := verifySaltStackConfiguration(rc, config); err != nil {
		return fmt.Errorf("failed to verify SaltStack configuration: %w", err)
	}

	logger.Info("SaltStack configuration generated successfully")
	return nil
}

// assessSaltStackPrerequisites checks if SaltStack is available and configured
func assessSaltStackPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if salt-call is available
	logger.Debug("Checking for salt-call executable")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"salt-call"},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("salt-call not found: please install SaltStack first using 'eos create saltstack'"))
	}
	logger.Debug("salt-call found", zap.String("path", strings.TrimSpace(output)))

	// Check if Salt directories exist
	logger.Debug("Checking Salt directory structure")
	requiredDirs := []string{
		"/srv/salt",
		"/srv/pillar",
		"/etc/salt",
	}

	for _, dir := range requiredDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("salt directory %s does not exist", dir))
		}
	}

	logger.Debug("SaltStack prerequisites satisfied")
	return nil
}

// generateSaltStackConfiguration creates the SaltStack configuration files
func generateSaltStackConfiguration(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create directory structure
	if err := createSaltDirectoryStructure(rc); err != nil {
		return fmt.Errorf("failed to create Salt directory structure: %w", err)
	}

	// Generate pillar data
	pillarData, err := generatePillarData(rc, config)
	if err != nil {
		return fmt.Errorf("failed to generate pillar data: %w", err)
	}

	// Write pillar file
	if err := writePillarFile(rc, pillarData); err != nil {
		return fmt.Errorf("failed to write pillar file: %w", err)
	}

	// Generate state files
	if err := generateStateFiles(rc, config); err != nil {
		return fmt.Errorf("failed to generate state files: %w", err)
	}

	// Generate Terraform templates
	if err := generateTerraformTemplates(rc, config); err != nil {
		return fmt.Errorf("failed to generate Terraform templates: %w", err)
	}

	logger.Info("SaltStack configuration generated successfully")
	return nil
}

// createSaltDirectoryStructure creates the necessary Salt directories
func createSaltDirectoryStructure(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	directories := []string{
		SaltCephStatesDir,
		SaltCephPillarDir,
		SaltCephTemplateDir,
		TerraformCephDir,
	}

	for _, dir := range directories {
		logger.Debug("Creating directory", zap.String("path", dir))
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// generatePillarData creates the pillar data for CephFS configuration
func generatePillarData(rc *eos_io.RuntimeContext, config *Config) (map[string]any, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Generating pillar data for CephFS deployment")

	// Generate cluster FSID if not provided
	clusterFSID := config.ClusterFSID
	if clusterFSID == "" {
		fsid, err := generateClusterFSID(rc)
		if err != nil {
			return nil, fmt.Errorf("failed to generate cluster FSID: %w", err)
		}
		clusterFSID = fsid
		config.ClusterFSID = fsid
	}

	pillarData := map[string]any{
		"ceph": map[string]any{
			"cluster_fsid":      clusterFSID,
			"admin_host":        config.AdminHost,
			"ssh_user":          config.SSHUser,
			"ceph_image":        config.CephImage,
			"public_network":    config.PublicNetwork,
			"cluster_network":   config.ClusterNetwork,
			"osd_devices":       config.OSDDevices,
			"objectstore":       config.GetObjectStore(),
			"osd_memory_target": config.GetOSDMemoryTarget(),
			"mon_count":         config.GetMONCount(),
			"mgr_count":         config.GetMGRCount(),
			"terraform_path":    TerraformCephDir,
		},
	}

	return pillarData, nil
}

// writePillarFile writes the pillar data to the pillar file
func writePillarFile(rc *eos_io.RuntimeContext, pillarData map[string]any) error {
	logger := otelzap.Ctx(rc.Ctx)

	pillarPath := GetSaltCephPillarPath()
	logger.Debug("Writing pillar file", zap.String("path", pillarPath))

	// Convert to YAML
	yamlData, err := yaml.Marshal(pillarData)
	if err != nil {
		return fmt.Errorf("failed to marshal pillar data: %w", err)
	}

	// Write to file
	if err := os.WriteFile(pillarPath, yamlData, 0644); err != nil {
		return fmt.Errorf("failed to write pillar file: %w", err)
	}

	logger.Debug("Pillar file written successfully")
	return nil
}

// generateStateFiles creates the SaltStack state files
func generateStateFiles(rc *eos_io.RuntimeContext, _ *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create main state file
	stateContent := `# CephFS deployment state
ceph_terraform_generation:
  cmd.run:
    - name: salt-call --local state.sls ceph.terraform
    - cwd: {{ pillar['ceph']['terraform_path'] }}
    - require:
      - file: terraform_template_rendered

terraform_template_rendered:
  file.managed:
    - name: {{ pillar['ceph']['terraform_path'] }}/main.tf
    - source: salt://ceph/templates/terraform.hcl.j2
    - template: jinja
    - context:
        cluster_fsid: {{ pillar['ceph']['cluster_fsid'] }}
        admin_host: {{ pillar['ceph']['admin_host'] }}
        ssh_user: {{ pillar['ceph']['ssh_user'] }}
        ceph_image: {{ pillar['ceph']['ceph_image'] }}
        public_network: {{ pillar['ceph']['public_network'] }}
        cluster_network: {{ pillar['ceph']['cluster_network'] }}
        osd_devices: {{ pillar['ceph']['osd_devices'] }}
        objectstore: {{ pillar['ceph']['objectstore'] }}
    - makedirs: True
    - mode: 644

ceph_terraform_directory:
  file.directory:
    - name: {{ pillar['ceph']['terraform_path'] }}
    - user: root
    - group: root
    - mode: 755
    - makedirs: True
`

	stateFile := filepath.Join(SaltCephStatesDir, "init.sls")
	logger.Debug("Writing state file", zap.String("path", stateFile))

	if err := os.WriteFile(stateFile, []byte(stateContent), 0644); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	return nil
}

// generateTerraformTemplates creates the Jinja2 templates for Terraform
func generateTerraformTemplates(rc *eos_io.RuntimeContext, _ *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	templateContent := `terraform {
  required_version = ">= 1.6.0"
  required_providers {
    ceph   = { source = "ceph/ceph", version = "0.7.4" }
    local  = { source = "hashicorp/local" }
    null   = { source = "hashicorp/null" }
  }
}

#########################
#  VARIABLES            #
#########################
variable "cluster_fsid"      { 
  type = string 
  default = "{{ cluster_fsid }}"
}
variable "admin_host"        { 
  type = string 
  default = "{{ admin_host }}"
}
variable "ssh_user"          { 
  type = string  
  default = "{{ ssh_user }}"
}
variable "ceph_image"        { 
  type = string  
  default = "{{ ceph_image }}"
}
variable "public_network"    { 
  type = string 
  default = "{{ public_network }}"
}
variable "cluster_network"   { 
  type = string 
  default = "{{ cluster_network }}"
}
variable "osd_devices"       { 
  type = list(string) 
  default = {{ osd_devices | tojson }}
}
variable "objectstore"       { 
  type = string 
  default = "{{ objectstore }}"
}

#########################
#  LOCAL DATA           #
#########################
locals {
  osd_spec = yamlencode({
    service_type : "osd"
    service_id   : "all-available-devices"
    placement    : { host_pattern : "*" }
    spec : {
      data_devices  : { 
        {% if osd_devices and osd_devices|length > 0 %}
        paths : var.osd_devices
        {% else %}
        all : true 
        {% endif %}
      }
      filter_logic  : "AND"
      objectstore   : var.objectstore
    }
  })
}

#########################
#  FILE RENDER          #
#########################
resource "local_file" "osd_spec_yaml" {
  content  = local.osd_spec
  filename = "${path.module}/osd-spec.yaml"
}

#########################
#  APPLY WITH cephadm   #
#########################
resource "null_resource" "apply_ceph_spec" {
  # re-run if either spec or image changes
  triggers = {
    spec_hash  = sha1(local.osd_spec)
    ceph_image = var.ceph_image
  }

  connection {
    type        = "ssh"
    user        = var.ssh_user
    host        = var.admin_host
    # ssh_key   = file("~/.ssh/id_rsa")   # or agent-forwarding
  }

  provisioner "file" {
    source      = local_file.osd_spec_yaml.filename
    destination = "/tmp/osd-spec.yaml"
  }

  provisioner "remote-exec" {
    inline = [
      # hold the image constant
      "cephadm set-repo --image ${var.ceph_image}",
      # apply cluster-wide networks first (only once!)
      "ceph config set mon public_network  ${var.public_network}",
      "ceph config set mon cluster_network ${var.cluster_network}",
      # now apply the spec
      "ceph orch apply -i /tmp/osd-spec.yaml"
    ]
  }
}

#########################
#  OUTPUTS              #
#########################
output "cluster_fsid" {
  value = var.cluster_fsid
}

output "admin_host" {
  value = var.admin_host
}

output "ceph_image" {
  value = var.ceph_image
}

output "osd_spec_content" {
  value = local.osd_spec
}
`

	templateFile := filepath.Join(SaltCephTemplateDir, "terraform.hcl.j2")
	logger.Debug("Writing Terraform template", zap.String("path", templateFile))

	if err := os.WriteFile(templateFile, []byte(templateContent), 0644); err != nil {
		return fmt.Errorf("failed to write Terraform template: %w", err)
	}

	return nil
}

// verifySaltStackConfiguration verifies the generated configuration
func verifySaltStackConfiguration(rc *eos_io.RuntimeContext, _ *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Verify pillar file exists and is valid
	pillarPath := GetSaltCephPillarPath()
	if _, err := os.Stat(pillarPath); os.IsNotExist(err) {
		return fmt.Errorf("pillar file was not created")
	}

	// Verify state file exists
	stateFile := filepath.Join(SaltCephStatesDir, "init.sls")
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		return fmt.Errorf("state file was not created")
	}

	// Verify Terraform template exists
	templateFile := filepath.Join(SaltCephTemplateDir, "terraform.hcl.j2")
	if _, err := os.Stat(templateFile); os.IsNotExist(err) {
		return fmt.Errorf("terraform template was not created")
	}

	// Test pillar data syntax
	logger.Debug("Testing pillar data syntax")
	if err := testPillarSyntax(rc); err != nil {
		return fmt.Errorf("pillar syntax test failed: %w", err)
	}

	logger.Debug("SaltStack configuration verification completed")
	return nil
}

// testPillarSyntax tests the pillar data syntax using salt-call
func testPillarSyntax(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Testing pillar data syntax with salt-call")

	// Use salt-call to test pillar data
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "pillar.items", "ceph"},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("pillar syntax test failed: %w", err)
	}

	if !strings.Contains(output, "ceph:") {
		return fmt.Errorf("pillar syntax test failed: ceph pillar not found in output")
	}

	logger.Debug("Pillar syntax test passed")
	return nil
}

// generateClusterFSID generates a new cluster FSID (UUID)
func generateClusterFSID(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Generating cluster FSID")

	// Use uuidgen to generate a UUID
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "uuidgen",
		Args:    []string{},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate UUID: %w", err)
	}

	fsid := strings.TrimSpace(output)
	logger.Debug("Generated cluster FSID", zap.String("fsid", fsid))

	return fsid, nil
}
