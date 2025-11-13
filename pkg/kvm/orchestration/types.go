//go:build linux

package orchestration

import (
	"time"
)

// VMRegistration represents a VM registration in Consul
type VMRegistration struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	IPAddress   string            `json:"ip_address"`
	Port        int               `json:"port"`
	Tags        []string          `json:"tags"`
	Meta        map[string]string `json:"meta"`
	HealthCheck *HealthCheck      `json:"health_check,omitempty"`
}

// HealthCheck configuration for Consul
type HealthCheck struct {
	TCP                            string        `json:"tcp,omitempty"`
	HTTP                           string        `json:"http,omitempty"`
	Interval                       time.Duration `json:"interval"`
	Timeout                        time.Duration `json:"timeout"`
	DeregisterCriticalServiceAfter time.Duration `json:"deregister_critical_service_after"`
}

// IPAllocation represents IP allocation from Consul KV
type IPAllocation struct {
	IP        string    `json:"ip"`
	VMName    string    `json:"vm_name"`
	Allocated time.Time `json:"allocated"`
	InUse     bool      `json:"in_use"`
}

// VMPool represents a pool of VMs for orchestration
type VMPool struct {
	Name         string        `json:"name"`
	MinSize      int           `json:"min_size"`
	MaxSize      int           `json:"max_size"`
	CurrentSize  int           `json:"current_size"`
	VMTemplate   string        `json:"vm_template"`
	Tags         []string      `json:"tags"`
	ScalingRules *ScalingRules `json:"scaling_rules,omitempty"`
}

// ScalingRules for VM pool management
type ScalingRules struct {
	CPUThresholdUp     float64       `json:"cpu_threshold_up"`
	CPUThresholdDown   float64       `json:"cpu_threshold_down"`
	MemThresholdUp     float64       `json:"mem_threshold_up"`
	MemThresholdDown   float64       `json:"mem_threshold_down"`
	ScaleUpIncrement   int           `json:"scale_up_increment"`
	ScaleDownDecrement int           `json:"scale_down_decrement"`
	CooldownPeriod     time.Duration `json:"cooldown_period"`
}

// NomadVMJob represents a Nomad job for VM workloads
type NomadVMJob struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	VMName      string            `json:"vm_name"`
	Type        string            `json:"type"` // service, batch, system
	Priority    int               `json:"priority"`
	Datacenters []string          `json:"datacenters"`
	Constraints []Constraint      `json:"constraints"`
	Meta        map[string]string `json:"meta"`
}

// Constraint for Nomad job placement
type Constraint struct {
	Attribute string `json:"attribute"`
	Operator  string `json:"operator"`
	Value     string `json:"value"`
}

// OrchestratedVM represents a VM managed by Consul and Nomad
type OrchestratedVM struct {
	Name            string            `json:"name"`
	IPAddress       string            `json:"ip_address"`
	ConsulServiceID string            `json:"consul_service_id"`
	NomadJobID      string            `json:"nomad_job_id,omitempty"`
	State           string            `json:"state"`
	Health          string            `json:"health"`
	CreatedAt       time.Time         `json:"created_at"`
	LastHealthCheck time.Time         `json:"last_health_check"`
	Meta            map[string]string `json:"meta"`
}

// IPRange represents a range of IPs for allocation
type IPRange struct {
	Network  string   `json:"network"`  // e.g., "192.168.122.0/24"
	Start    string   `json:"start"`    // e.g., "192.168.122.100"
	End      string   `json:"end"`      // e.g., "192.168.122.200"
	Reserved []string `json:"reserved"` // IPs to never allocate
}
