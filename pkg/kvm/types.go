// pkg/kvm/types.go
package kvm

import "time"

// Constants & defaults
const (
	DefaultTenantUsername = "debugadmin"
	VmPrefix              = "vm-tenant-"
	KsTemplatePath        = "/srv/iso/autoinstall-tenant.ks"
	IsoDefaultPath        = "/srv/iso/CentOS-Stream-9-latest-x86_64-dvd1.iso"
	ImageDir              = "/var/lib/libvirt/images"
	VmBaseIDFile          = "/var/lib/libvirt/next_vm_id"
)

// CloudInitConfig holds everything needed to seed a VM via cloud-init.
type CloudInitConfig struct {
	VMName     string // e.g. “vm-tenant-001”
	CloudImg   string // path to the base cloud image
	PublicKey  string // either a path or literal ssh‐public‐key
	DiskSizeGB int    // e.g. 20
	UseUEFI    bool   // default: true
}

// KickstartTemplateData is what you pass into your ks template.
type KickstartTemplateData struct {
	Username string
	Password string
	SSHKey   string
	Hostname string
}

// VM models both your “read kvm” output *and* your GORM table.
type VM struct {
	VMName     string    `gorm:"primaryKey;column:vm_name"`  // domain name
	State      string    `gorm:"column:state"`               // running/shut off
	Network    string    `gorm:"column:network"`             // e.g. default
	MACAddress string    `gorm:"column:mac_address;size:17"` // 52:54:…
	Protocol   string    `gorm:"column:protocol;size:10"`    // ipv4/ipv6
	IPAddress  string    `gorm:"column:ip_address;size:45"`  // 192.168.122.34
	CreatedAt  time.Time `gorm:"autoCreateTime;column:created_at"`
	UpdatedAt  time.Time `gorm:"autoUpdateTime;column:updated_at"`
}

type VMEntry struct {
	Name       string
	State      string
	Network    string
	MACAddress string
	Protocol   string
	IPAddress  string
}

// Runtime configuration set by flags (e.g. in cobra command init)
var (
	// TenantDistro is the OS type used to determine virt-install options
	TenantDistro = "centos-stream9"

	// IsoPathOverride defines the full ISO path used for provisioning
	IsoPathOverride = IsoDefaultPath

	// SshKeyOverride is the SSH public key path injected into tenant VMs
	SshKeyOverride string

	// UserProvidedVMName lets users override the default auto-naming
	UserProvidedVMName string
)

type TenantConfig struct {
	Distro     string
	ISOPath    string
	SSHKeyPath string
	VMName     string
}
