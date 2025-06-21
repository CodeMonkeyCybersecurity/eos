package inspect

import (
	"time"
)

// Infrastructure represents the complete infrastructure audit
type Infrastructure struct {
	Timestamp time.Time     `yaml:"timestamp" json:"timestamp"`
	Hostname  string        `yaml:"hostname" json:"hostname"`
	System    *SystemInfo   `yaml:"system" json:"system"`
	Docker    *DockerInfo   `yaml:"docker,omitempty" json:"docker,omitempty"`
	KVM       *KVMInfo      `yaml:"kvm,omitempty" json:"kvm,omitempty"`
	Hetzner   *HetznerInfo  `yaml:"hetzner,omitempty" json:"hetzner,omitempty"`
	Services  *ServicesInfo `yaml:"services,omitempty" json:"services,omitempty"`
}

// SystemInfo contains basic system information
type SystemInfo struct {
	Hostname     string        `yaml:"hostname" json:"hostname"`
	OS           string        `yaml:"os" json:"os"`
	OSVersion    string        `yaml:"os_version" json:"os_version"`
	Kernel       string        `yaml:"kernel" json:"kernel"`
	Architecture string        `yaml:"architecture" json:"architecture"`
	Uptime       string        `yaml:"uptime" json:"uptime"`
	CPU          CPUInfo       `yaml:"cpu" json:"cpu"`
	Memory       MemoryInfo    `yaml:"memory" json:"memory"`
	Disks        []DiskInfo    `yaml:"disks" json:"disks"`
	Networks     []NetworkInfo `yaml:"networks" json:"networks"`
	Routes       []RouteInfo   `yaml:"routes" json:"routes"`
}

// CPUInfo contains CPU information
type CPUInfo struct {
	Model   string `yaml:"model" json:"model"`
	Count   int    `yaml:"count" json:"count"`
	Cores   int    `yaml:"cores" json:"cores"`
	Threads int    `yaml:"threads" json:"threads"`
}

// MemoryInfo contains memory information
type MemoryInfo struct {
	Total     string `yaml:"total" json:"total"`
	Used      string `yaml:"used" json:"used"`
	Free      string `yaml:"free" json:"free"`
	Available string `yaml:"available" json:"available"`
	SwapTotal string `yaml:"swap_total" json:"swap_total"`
	SwapUsed  string `yaml:"swap_used" json:"swap_used"`
}

// DiskInfo contains disk information
type DiskInfo struct {
	Filesystem string `yaml:"filesystem" json:"filesystem"`
	Type       string `yaml:"type" json:"type"`
	Size       string `yaml:"size" json:"size"`
	Used       string `yaml:"used" json:"used"`
	Available  string `yaml:"available" json:"available"`
	UsePercent string `yaml:"use_percent" json:"use_percent"`
	MountPoint string `yaml:"mount_point" json:"mount_point"`
}

// NetworkInfo contains network interface information
type NetworkInfo struct {
	Interface string   `yaml:"interface" json:"interface"`
	State     string   `yaml:"state" json:"state"`
	MAC       string   `yaml:"mac" json:"mac"`
	IPs       []string `yaml:"ips" json:"ips"`
	MTU       int      `yaml:"mtu" json:"mtu"`
}

// RouteInfo contains routing information
type RouteInfo struct {
	Destination string `yaml:"destination" json:"destination"`
	Gateway     string `yaml:"gateway" json:"gateway"`
	Interface   string `yaml:"interface" json:"interface"`
	Metric      int    `yaml:"metric" json:"metric"`
}

// DockerInfo contains Docker infrastructure information
type DockerInfo struct {
	Version      string            `yaml:"version" json:"version"`
	Containers   []DockerContainer `yaml:"containers" json:"containers"`
	Images       []DockerImage     `yaml:"images" json:"images"`
	Networks     []DockerNetwork   `yaml:"networks" json:"networks"`
	Volumes      []DockerVolume    `yaml:"volumes" json:"volumes"`
	ComposeFiles []ComposeFile     `yaml:"compose_files,omitempty" json:"compose_files,omitempty"`
}

// DockerContainer represents a Docker container
type DockerContainer struct {
	ID          string            `yaml:"id" json:"id"`
	Name        string            `yaml:"name" json:"name"`
	Image       string            `yaml:"image" json:"image"`
	Status      string            `yaml:"status" json:"status"`
	State       string            `yaml:"state" json:"state"`
	Created     time.Time         `yaml:"created" json:"created"`
	Ports       []string          `yaml:"ports,omitempty" json:"ports,omitempty"`
	Networks    []string          `yaml:"networks,omitempty" json:"networks,omitempty"`
	Volumes     []string          `yaml:"volumes,omitempty" json:"volumes,omitempty"`
	Environment map[string]string `yaml:"environment,omitempty" json:"environment,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Command     string            `yaml:"command,omitempty" json:"command,omitempty"`
	Restart     string            `yaml:"restart_policy,omitempty" json:"restart_policy,omitempty"`
}

// DockerImage represents a Docker image
type DockerImage struct {
	ID       string    `yaml:"id" json:"id"`
	RepoTags []string  `yaml:"repo_tags" json:"repo_tags"`
	Size     int64     `yaml:"size" json:"size"`
	Created  time.Time `yaml:"created" json:"created"`
}

// DockerNetwork represents a Docker network
type DockerNetwork struct {
	ID     string            `yaml:"id" json:"id"`
	Name   string            `yaml:"name" json:"name"`
	Driver string            `yaml:"driver" json:"driver"`
	Scope  string            `yaml:"scope" json:"scope"`
	Labels map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// DockerVolume represents a Docker volume
type DockerVolume struct {
	Name       string            `yaml:"name" json:"name"`
	Driver     string            `yaml:"driver" json:"driver"`
	MountPoint string            `yaml:"mount_point" json:"mount_point"`
	Labels     map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// ComposeFile represents a docker-compose configuration
type ComposeFile struct {
	Path     string                 `yaml:"path" json:"path"`
	Services map[string]interface{} `yaml:"services" json:"services"`
}

// KVMInfo contains KVM/Libvirt infrastructure information
type KVMInfo struct {
	LibvirtVersion string       `yaml:"libvirt_version" json:"libvirt_version"`
	VMs            []KVMDomain  `yaml:"vms" json:"vms"`
	Networks       []KVMNetwork `yaml:"networks" json:"networks"`
	StoragePools   []KVMPool    `yaml:"storage_pools" json:"storage_pools"`
}

// KVMDomain represents a KVM virtual machine
type KVMDomain struct {
	Name       string         `yaml:"name" json:"name"`
	UUID       string         `yaml:"uuid" json:"uuid"`
	State      string         `yaml:"state" json:"state"`
	CPUs       int            `yaml:"cpus" json:"cpus"`
	Memory     string         `yaml:"memory" json:"memory"`
	OSType     string         `yaml:"os_type" json:"os_type"`
	Disks      []KVMDisk      `yaml:"disks" json:"disks"`
	Interfaces []KVMInterface `yaml:"interfaces" json:"interfaces"`
}

// KVMDisk represents a VM disk
type KVMDisk struct {
	Device string `yaml:"device" json:"device"`
	Path   string `yaml:"path" json:"path"`
	Format string `yaml:"format" json:"format"`
	Size   string `yaml:"size" json:"size"`
	Bus    string `yaml:"bus" json:"bus"`
}

// KVMInterface represents a VM network interface
type KVMInterface struct {
	Type   string `yaml:"type" json:"type"`
	MAC    string `yaml:"mac" json:"mac"`
	Source string `yaml:"source" json:"source"`
	Model  string `yaml:"model" json:"model"`
}

// KVMNetwork represents a libvirt network
type KVMNetwork struct {
	Name       string `yaml:"name" json:"name"`
	UUID       string `yaml:"uuid" json:"uuid"`
	Active     bool   `yaml:"active" json:"active"`
	Persistent bool   `yaml:"persistent" json:"persistent"`
	Bridge     string `yaml:"bridge,omitempty" json:"bridge,omitempty"`
}

// KVMPool represents a storage pool
type KVMPool struct {
	Name       string `yaml:"name" json:"name"`
	UUID       string `yaml:"uuid" json:"uuid"`
	State      string `yaml:"state" json:"state"`
	Capacity   string `yaml:"capacity" json:"capacity"`
	Allocation string `yaml:"allocation" json:"allocation"`
	Available  string `yaml:"available" json:"available"`
	Path       string `yaml:"path,omitempty" json:"path,omitempty"`
}

// HetznerInfo contains Hetzner Cloud infrastructure information
type HetznerInfo struct {
	Servers       []HetznerServer       `yaml:"servers,omitempty" json:"servers,omitempty"`
	Networks      []HetznerNetwork      `yaml:"networks,omitempty" json:"networks,omitempty"`
	Firewalls     []HetznerFirewall     `yaml:"firewalls,omitempty" json:"firewalls,omitempty"`
	LoadBalancers []HetznerLoadBalancer `yaml:"load_balancers,omitempty" json:"load_balancers,omitempty"`
	Volumes       []HetznerVolume       `yaml:"volumes,omitempty" json:"volumes,omitempty"`
	FloatingIPs   []HetznerFloatingIP   `yaml:"floating_ips,omitempty" json:"floating_ips,omitempty"`
}

// HetznerServer represents a Hetzner cloud server
type HetznerServer struct {
	ID         int               `yaml:"id" json:"id"`
	Name       string            `yaml:"name" json:"name"`
	Status     string            `yaml:"status" json:"status"`
	ServerType string            `yaml:"server_type" json:"server_type"`
	Image      string            `yaml:"image" json:"image"`
	Datacenter string            `yaml:"datacenter" json:"datacenter"`
	Location   string            `yaml:"location" json:"location"`
	PublicIP   string            `yaml:"public_ip" json:"public_ip"`
	PrivateIPs []string          `yaml:"private_ips,omitempty" json:"private_ips,omitempty"`
	Labels     map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Created    time.Time         `yaml:"created" json:"created"`
}

// HetznerNetwork represents a Hetzner network
type HetznerNetwork struct {
	ID      int               `yaml:"id" json:"id"`
	Name    string            `yaml:"name" json:"name"`
	IPRange string            `yaml:"ip_range" json:"ip_range"`
	Subnets []HetznerSubnet   `yaml:"subnets" json:"subnets"`
	Labels  map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// HetznerSubnet represents a network subnet
type HetznerSubnet struct {
	Type        string `yaml:"type" json:"type"`
	NetworkZone string `yaml:"network_zone" json:"network_zone"`
	IPRange     string `yaml:"ip_range" json:"ip_range"`
}

// HetznerFirewall represents a Hetzner firewall
type HetznerFirewall struct {
	ID     int                   `yaml:"id" json:"id"`
	Name   string                `yaml:"name" json:"name"`
	Rules  []HetznerFirewallRule `yaml:"rules" json:"rules"`
	Labels map[string]string     `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// HetznerFirewallRule represents a firewall rule
type HetznerFirewallRule struct {
	Direction      string   `yaml:"direction" json:"direction"`
	Protocol       string   `yaml:"protocol" json:"protocol"`
	Port           string   `yaml:"port,omitempty" json:"port,omitempty"`
	SourceIPs      []string `yaml:"source_ips,omitempty" json:"source_ips,omitempty"`
	DestinationIPs []string `yaml:"destination_ips,omitempty" json:"destination_ips,omitempty"`
}

// HetznerLoadBalancer represents a load balancer
type HetznerLoadBalancer struct {
	ID       int               `yaml:"id" json:"id"`
	Name     string            `yaml:"name" json:"name"`
	PublicIP string            `yaml:"public_ip" json:"public_ip"`
	Location string            `yaml:"location" json:"location"`
	Type     string            `yaml:"type" json:"type"`
	Labels   map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// HetznerVolume represents a Hetzner volume
type HetznerVolume struct {
	ID       int               `yaml:"id" json:"id"`
	Name     string            `yaml:"name" json:"name"`
	Size     int               `yaml:"size" json:"size"`
	Server   *int              `yaml:"server,omitempty" json:"server,omitempty"`
	Location string            `yaml:"location" json:"location"`
	Labels   map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// HetznerFloatingIP represents a floating IP
type HetznerFloatingIP struct {
	ID       int               `yaml:"id" json:"id"`
	Name     string            `yaml:"name" json:"name"`
	IP       string            `yaml:"ip" json:"ip"`
	Type     string            `yaml:"type" json:"type"`
	Server   *int              `yaml:"server,omitempty" json:"server,omitempty"`
	Location string            `yaml:"location" json:"location"`
	Labels   map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// ServicesInfo contains service configuration information
type ServicesInfo struct {
	SystemdServices []SystemdService `yaml:"systemd_services" json:"systemd_services"`
	Nginx           *NginxInfo       `yaml:"nginx,omitempty" json:"nginx,omitempty"`
	Apache          *ApacheInfo      `yaml:"apache,omitempty" json:"apache,omitempty"`
	Caddy           *CaddyInfo       `yaml:"caddy,omitempty" json:"caddy,omitempty"`
	PostgreSQL      *PostgreSQLInfo  `yaml:"postgresql,omitempty" json:"postgresql,omitempty"`
	MySQL           *MySQLInfo       `yaml:"mysql,omitempty" json:"mysql,omitempty"`
	Redis           *RedisInfo       `yaml:"redis,omitempty" json:"redis,omitempty"`
	HashiCorp       *HashiCorpInfo   `yaml:"hashicorp,omitempty" json:"hashicorp,omitempty"`
	Tailscale       *TailscaleInfo   `yaml:"tailscale,omitempty" json:"tailscale,omitempty"`
}

// SystemdService represents a systemd service
type SystemdService struct {
	Name        string `yaml:"name" json:"name"`
	State       string `yaml:"state" json:"state"`
	SubState    string `yaml:"sub_state" json:"sub_state"`
	Description string `yaml:"description" json:"description"`
	LoadState   string `yaml:"load_state" json:"load_state"`
	ActiveState string `yaml:"active_state" json:"active_state"`
}

// NginxInfo contains Nginx configuration
type NginxInfo struct {
	Version    string   `yaml:"version" json:"version"`
	ConfigPath string   `yaml:"config_path" json:"config_path"`
	Sites      []string `yaml:"sites" json:"sites"`
	Upstreams  []string `yaml:"upstreams,omitempty" json:"upstreams,omitempty"`
}

// ApacheInfo contains Apache configuration
type ApacheInfo struct {
	Version    string   `yaml:"version" json:"version"`
	ConfigPath string   `yaml:"config_path" json:"config_path"`
	Sites      []string `yaml:"sites" json:"sites"`
	Modules    []string `yaml:"modules" json:"modules"`
}

// CaddyInfo contains Caddy configuration
type CaddyInfo struct {
	Version    string   `yaml:"version" json:"version"`
	ConfigPath string   `yaml:"config_path" json:"config_path"`
	Sites      []string `yaml:"sites" json:"sites"`
}

// PostgreSQLInfo contains PostgreSQL information
type PostgreSQLInfo struct {
	Version   string   `yaml:"version" json:"version"`
	Port      int      `yaml:"port" json:"port"`
	DataDir   string   `yaml:"data_dir" json:"data_dir"`
	Databases []string `yaml:"databases" json:"databases"`
}

// MySQLInfo contains MySQL information
type MySQLInfo struct {
	Version   string   `yaml:"version" json:"version"`
	Port      int      `yaml:"port" json:"port"`
	DataDir   string   `yaml:"data_dir" json:"data_dir"`
	Databases []string `yaml:"databases" json:"databases"`
}

// RedisInfo contains Redis information
type RedisInfo struct {
	Version string `yaml:"version" json:"version"`
	Port    int    `yaml:"port" json:"port"`
	Memory  string `yaml:"memory" json:"memory"`
}

// HashiCorpInfo contains HashiCorp tools information
type HashiCorpInfo struct {
	Vault    *HashiCorpTool `yaml:"vault,omitempty" json:"vault,omitempty"`
	Consul   *HashiCorpTool `yaml:"consul,omitempty" json:"consul,omitempty"`
	Nomad    *HashiCorpTool `yaml:"nomad,omitempty" json:"nomad,omitempty"`
	Boundary *HashiCorpTool `yaml:"boundary,omitempty" json:"boundary,omitempty"`
}

// HashiCorpTool represents a HashiCorp tool installation
type HashiCorpTool struct {
	Version    string `yaml:"version" json:"version"`
	ConfigPath string `yaml:"config_path" json:"config_path"`
	Status     string `yaml:"status" json:"status"`
}

// TailscaleInfo contains Tailscale information
type TailscaleInfo struct {
	Version  string          `yaml:"version" json:"version"`
	Status   string          `yaml:"status" json:"status"`
	Tailnet  string          `yaml:"tailnet,omitempty" json:"tailnet,omitempty"`
	IP       string          `yaml:"ip,omitempty" json:"ip,omitempty"`
	Hostname string          `yaml:"hostname,omitempty" json:"hostname,omitempty"`
	Peers    []TailscalePeer `yaml:"peers,omitempty" json:"peers,omitempty"`
}

// TailscalePeer represents a Tailscale peer
type TailscalePeer struct {
	Name   string `yaml:"name" json:"name"`
	IP     string `yaml:"ip" json:"ip"`
	Online bool   `yaml:"online" json:"online"`
	OS     string `yaml:"os,omitempty" json:"os,omitempty"`
}
