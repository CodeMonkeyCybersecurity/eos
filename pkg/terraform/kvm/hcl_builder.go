// pkg/terraform/kvm/hcl_builder.go

package kvm

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"github.com/zclconf/go-cty/cty"
	"go.uber.org/zap"
)

// HCLBuilder provides a structured way to build Terraform HCL configurations
type HCLBuilder struct {
	file   *hclwrite.File
	body   *hclwrite.Body
	logger otelzap.LoggerWithCtx
}

// NewHCLBuilder creates a new HCL configuration builder
func NewHCLBuilder(logger otelzap.LoggerWithCtx) *HCLBuilder {
	file := hclwrite.NewEmptyFile()
	return &HCLBuilder{
		file:   file,
		body:   file.Body(),
		logger: logger,
	}
}

// AddCloudInitDisk adds a libvirt_cloudinit_disk resource
func (b *HCLBuilder) AddCloudInitDisk(name, pool, userData, metaData string) error {
	b.logger.Debug("Adding cloud-init disk resource",
		zap.String("name", name),
		zap.String("pool", pool))

	resourceName := fmt.Sprintf("%s_cloudinit", name)
	block := b.body.AppendNewBlock("resource", []string{"libvirt_cloudinit_disk", resourceName})
	body := block.Body()

	body.SetAttributeValue("name", cty.StringVal(fmt.Sprintf("%s-cloudinit.iso", name)))
	body.SetAttributeValue("pool", cty.StringVal(pool))

	// For heredocs, we need to use raw tokens
	// This ensures proper formatting without escaping
	userDataTokens := hclwrite.Tokens{
		{Type: hclsyntax.TokenIdent, Bytes: []byte("<<-EOF")},
		{Type: hclsyntax.TokenNewline, Bytes: []byte("\n")},
		{Type: hclsyntax.TokenIdent, Bytes: []byte(userData)},
		{Type: hclsyntax.TokenNewline, Bytes: []byte("\n")},
		{Type: hclsyntax.TokenIdent, Bytes: []byte("EOF")},
	}
	body.SetAttributeRaw("user_data", userDataTokens)

	metaDataTokens := hclwrite.Tokens{
		{Type: hclsyntax.TokenIdent, Bytes: []byte("<<-EOF")},
		{Type: hclsyntax.TokenNewline, Bytes: []byte("\n")},
		{Type: hclsyntax.TokenIdent, Bytes: []byte(metaData)},
		{Type: hclsyntax.TokenNewline, Bytes: []byte("\n")},
		{Type: hclsyntax.TokenIdent, Bytes: []byte("EOF")},
	}
	body.SetAttributeRaw("meta_data", metaDataTokens)

	// Add newline after resource
	b.body.AppendNewline()

	return nil
}

// AddVolume adds a libvirt_volume resource
func (b *HCLBuilder) AddVolume(name, pool string, sizeBytes int64, format string, encrypted bool, encryptionKey string) error {
	b.logger.Debug("Adding volume resource",
		zap.String("name", name),
		zap.Int64("size", sizeBytes),
		zap.Bool("encrypted", encrypted))

	resourceName := fmt.Sprintf("%s_disk", name)
	block := b.body.AppendNewBlock("resource", []string{"libvirt_volume", resourceName})
	body := block.Body()

	body.SetAttributeValue("name", cty.StringVal(fmt.Sprintf("%s-disk.qcow2", name)))
	body.SetAttributeValue("pool", cty.StringVal(pool))
	body.SetAttributeValue("size", cty.NumberIntVal(sizeBytes))
	body.SetAttributeValue("format", cty.StringVal(format))

	if encrypted {
		encBlock := body.AppendNewBlock("encryption", nil)
		encBody := encBlock.Body()

		if encryptionKey == "" {
			// Use Terraform's uuid() function
			encBody.SetAttributeRaw("secret", hclwrite.Tokens{
				{Type: hclsyntax.TokenIdent, Bytes: []byte("${uuid()}")},
			})
		} else {
			encBody.SetAttributeValue("secret", cty.StringVal(encryptionKey))
		}
		encBody.SetAttributeValue("cipher", cty.StringVal("aes-256-xts-plain64"))
		encBody.SetAttributeValue("size", cty.NumberIntVal(512))
	}

	// Add newline after resource
	b.body.AppendNewline()

	return nil
}

// AddAdditionalVolume adds additional storage volumes
func (b *HCLBuilder) AddAdditionalVolume(vmName string, index int, vol VolumeConfig) error {
	resourceName := fmt.Sprintf("%s_volume_%d", vmName, index)
	block := b.body.AppendNewBlock("resource", []string{"libvirt_volume", resourceName})
	body := block.Body()

	body.SetAttributeValue("name", cty.StringVal(fmt.Sprintf("%s-%s.%s", vmName, vol.Name, vol.Format)))
	body.SetAttributeValue("pool", cty.StringVal(vol.Pool))
	body.SetAttributeValue("size", cty.NumberIntVal(int64(vol.Size)))
	body.SetAttributeValue("format", cty.StringVal(vol.Format))

	// Add newline after resource
	b.body.AppendNewline()

	return nil
}

// AddDomain adds a libvirt_domain resource (the VM itself)
func (b *HCLBuilder) AddDomain(config *VMConfig) error {
	b.logger.Debug("Adding domain resource",
		zap.String("name", config.Name),
		zap.Uint("memory", config.Memory),
		zap.Uint("vcpus", config.VCPUs))

	block := b.body.AppendNewBlock("resource", []string{"libvirt_domain", config.Name})
	body := block.Body()

	// Basic configuration
	body.SetAttributeValue("name", cty.StringVal(config.Name))
	body.SetAttributeValue("memory", cty.NumberIntVal(int64(config.Memory)))
	body.SetAttributeValue("vcpu", cty.NumberIntVal(int64(config.VCPUs)))

	// Cloud-init reference
	body.SetAttributeRaw("cloudinit", hclwrite.Tokens{
		{Type: hclsyntax.TokenIdent, Bytes: []byte(fmt.Sprintf("libvirt_cloudinit_disk.%s_cloudinit.id", config.Name))},
	})

	// Network configuration
	netBlock := body.AppendNewBlock("network_interface", nil)
	netBody := netBlock.Body()
	netBody.SetAttributeValue("network_name", cty.StringVal(config.NetworkName))

	// Main disk
	diskBlock := body.AppendNewBlock("disk", nil)
	diskBody := diskBlock.Body()
	diskBody.SetAttributeRaw("volume_id", hclwrite.Tokens{
		{Type: hclsyntax.TokenIdent, Bytes: []byte(fmt.Sprintf("libvirt_volume.%s_disk.id", config.Name))},
	})

	// Additional volumes
	for i := range config.Volumes {
		volBlock := body.AppendNewBlock("disk", nil)
		volBody := volBlock.Body()
		volBody.SetAttributeRaw("volume_id", hclwrite.Tokens{
			{Type: hclsyntax.TokenIdent, Bytes: []byte(fmt.Sprintf("libvirt_volume.%s_volume_%d.id", config.Name, i))},
		})
	}

	// Console configuration
	b.addConsoleConfig(body)

	// Graphics configuration
	b.addGraphicsConfig(body)

	// CPU configuration
	cpuBlock := body.AppendNewBlock("cpu", nil)
	cpuBody := cpuBlock.Body()
	cpuBody.SetAttributeValue("mode", cty.StringVal("host-passthrough"))

	// RNG device for better entropy
	rngBlock := body.AppendNewBlock("rng", nil)
	rngBody := rngBlock.Body()
	rngBody.SetAttributeValue("backend", cty.StringVal("/dev/urandom"))
	rngBody.SetAttributeValue("model", cty.StringVal("virtio"))

	// TPM configuration if enabled
	if config.EnableTPM {
		b.addTPMConfig(body)
	}

	// Firmware configuration for secure boot
	if config.SecureBoot {
		b.addSecureBootConfig(body)
	}

	// Set autostart
	body.SetAttributeValue("autostart", cty.BoolVal(config.AutoStart))

	return nil
}

// addConsoleConfig adds console configuration blocks
func (b *HCLBuilder) addConsoleConfig(body *hclwrite.Body) {
	// Serial console
	serialBlock := body.AppendNewBlock("console", nil)
	serialBody := serialBlock.Body()
	serialBody.SetAttributeValue("type", cty.StringVal("pty"))
	serialBody.SetAttributeValue("target_port", cty.StringVal("0"))
	serialBody.SetAttributeValue("target_type", cty.StringVal("serial"))

	// Virtio console
	virtioBlock := body.AppendNewBlock("console", nil)
	virtioBody := virtioBlock.Body()
	virtioBody.SetAttributeValue("type", cty.StringVal("pty"))
	virtioBody.SetAttributeValue("target_type", cty.StringVal("virtio"))
	virtioBody.SetAttributeValue("target_port", cty.StringVal("1"))
}

// addGraphicsConfig adds graphics configuration
func (b *HCLBuilder) addGraphicsConfig(body *hclwrite.Body) {
	graphicsBlock := body.AppendNewBlock("graphics", nil)
	graphicsBody := graphicsBlock.Body()
	graphicsBody.SetAttributeValue("type", cty.StringVal("spice"))
	graphicsBody.SetAttributeValue("listen_type", cty.StringVal("address"))
	graphicsBody.SetAttributeValue("autoport", cty.BoolVal(true))
	graphicsBody.SetAttributeValue("listen_address", cty.StringVal("127.0.0.1"))
}

// addTPMConfig adds TPM configuration
func (b *HCLBuilder) addTPMConfig(body *hclwrite.Body) {
	tpmBlock := body.AppendNewBlock("tpm", nil)
	tpmBody := tpmBlock.Body()
	tpmBody.SetAttributeValue("backend_type", cty.StringVal("emulator"))
	tpmBody.SetAttributeValue("backend_version", cty.StringVal("2.0"))
}

// addSecureBootConfig adds secure boot firmware configuration
func (b *HCLBuilder) addSecureBootConfig(body *hclwrite.Body) {
	// Check for UEFI firmware paths
	uefiPaths := []string{
		"/usr/share/OVMF/OVMF_CODE.secboot.fd",
		"/usr/share/edk2-ovmf/x64/OVMF_CODE.secboot.fd",
		"/usr/share/qemu/OVMF_CODE.secboot.fd",
	}

	var firmwarePath string
	for _, path := range uefiPaths {
		// In a real implementation, we'd check if the file exists
		// For now, use the most common path
		firmwarePath = path
		break
	}

	if firmwarePath != "" {
		body.SetAttributeValue("firmware", cty.StringVal(firmwarePath))

		// Add NVRAM template
		nvramBlock := body.AppendNewBlock("nvram", nil)
		nvramBody := nvramBlock.Body()
		nvramTemplate := strings.Replace(firmwarePath, "OVMF_CODE", "OVMF_VARS", 1)
		nvramBody.SetAttributeValue("template", cty.StringVal(nvramTemplate))
	}
}

// Bytes returns the generated HCL configuration as bytes
func (b *HCLBuilder) Bytes() []byte {
	return b.file.Bytes()
}

// String returns the generated HCL configuration as a string
func (b *HCLBuilder) String() string {
	return string(b.file.Bytes())
}