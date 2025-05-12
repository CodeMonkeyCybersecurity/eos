// pkg/kvm/types.go

package kvm

type CloudInitConfig struct {
	VMName     string
	CloudImg   string // e.g. /srv/iso/ubuntu-22.04-server-cloudimg-amd64.img
	PublicKey  string // path to .pub file or literal key string
	DiskSizeGB int    // e.g. 20
	UseUEFI    bool   // default: true
}

var SshKeyOverride string
var TenantDistro string
var UserProvidedVMName string

var (
	VmPrefix = "vm-tenant-"
)

const (
	KsTemplatePath = "/srv/iso/autoinstall-tenant.ks"
	IsoDefaultPath = "/srv/iso/CentOS-Stream-9-latest-x86_64-dvd1.iso"
	ImageDir       = "/var/lib/libvirt/images"
	VmBaseIDFile   = "/var/lib/libvirt/next_vm_id"
)

type TemplateContext struct {
	SSHKey   string
	VMName   string
	Hostname string
}

var IsoPathOverride string

const DefaultTenantUsername = "debugadmin"
