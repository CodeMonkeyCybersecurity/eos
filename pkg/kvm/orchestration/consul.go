package orchestration

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConsulOrchestrator manages VM orchestration through Consul
type ConsulOrchestrator struct {
	client      *api.Client
	logger      otelzap.LoggerWithCtx
	rc          *eos_io.RuntimeContext
	ipAllocMux  sync.Mutex
	ipRange     *IPRange
}

// NewConsulOrchestrator creates a new Consul orchestrator
func NewConsulOrchestrator(rc *eos_io.RuntimeContext, consulAddr string) (*ConsulOrchestrator, error) {
	logger := otelzap.Ctx(rc.Ctx)

	config := api.DefaultConfig()
	if consulAddr != "" {
		config.Address = consulAddr
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Test connection
	leader, err := client.Status().Leader()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Consul: %w", err)
	}

	logger.Info("Connected to Consul cluster",
		zap.String("leader", leader),
		zap.String("address", config.Address))

	return &ConsulOrchestrator{
		client: client,
		logger: logger,
		rc:     rc,
		ipRange: &IPRange{
			Network: "192.168.122.0/24",
			Start:   "192.168.122.100",
			End:     "192.168.122.200",
			Reserved: []string{
				"192.168.122.1",   // Gateway
				"192.168.122.255", // Broadcast
			},
		},
	}, nil
}

// SetIPRange configures the IP range for allocation
func (co *ConsulOrchestrator) SetIPRange(ipRange *IPRange) {
	co.ipAllocMux.Lock()
	defer co.ipAllocMux.Unlock()
	co.ipRange = ipRange
}

// RegisterVM registers a VM with Consul
func (co *ConsulOrchestrator) RegisterVM(vm *VMRegistration) error {
	co.logger.Info("Registering VM with Consul",
		zap.String("vm_name", vm.Name),
		zap.String("ip", vm.IPAddress))

	// Create service registration
	registration := &api.AgentServiceRegistration{
		ID:      vm.ID,
		Name:    fmt.Sprintf("vm-%s", vm.Name),
		Port:    vm.Port,
		Address: vm.IPAddress,
		Tags:    vm.Tags,
		Meta:    vm.Meta,
	}

	// Add health check if provided
	if vm.HealthCheck != nil {
		check := &api.AgentServiceCheck{
			CheckID:                        fmt.Sprintf("%s-health", vm.ID),
			Interval:                       vm.HealthCheck.Interval.String(),
			Timeout:                        vm.HealthCheck.Timeout.String(),
			DeregisterCriticalServiceAfter: vm.HealthCheck.DeregisterCriticalServiceAfter.String(),
		}

		if vm.HealthCheck.TCP != "" {
			check.TCP = vm.HealthCheck.TCP
		} else if vm.HealthCheck.HTTP != "" {
			check.HTTP = vm.HealthCheck.HTTP
		}

		registration.Check = check
	}

	// Register the service
	if err := co.client.Agent().ServiceRegister(registration); err != nil {
		return fmt.Errorf("failed to register VM with Consul: %w", err)
	}

	// Store VM metadata in KV
	kvData := map[string]interface{}{
		"name":       vm.Name,
		"ip_address": vm.IPAddress,
		"registered": time.Now().Unix(),
		"tags":       vm.Tags,
		"meta":       vm.Meta,
	}

	data, err := json.Marshal(kvData)
	if err != nil {
		return fmt.Errorf("failed to marshal VM data: %w", err)
	}

	kvPair := &api.KVPair{
		Key:   fmt.Sprintf("vms/%s/metadata", vm.Name),
		Value: data,
	}

	if _, err := co.client.KV().Put(kvPair, nil); err != nil {
		return fmt.Errorf("failed to store VM metadata in Consul: %w", err)
	}

	co.logger.Info("VM registered successfully",
		zap.String("vm_name", vm.Name),
		zap.String("service_id", vm.ID))

	return nil
}

// DeregisterVM removes a VM from Consul
func (co *ConsulOrchestrator) DeregisterVM(vmName string) error {
	co.logger.Info("Deregistering VM from Consul", zap.String("vm_name", vmName))

	// Deregister the service
	serviceID := fmt.Sprintf("vm-%s", vmName)
	if err := co.client.Agent().ServiceDeregister(serviceID); err != nil {
		return fmt.Errorf("failed to deregister VM from Consul: %w", err)
	}

	// Release IP allocation
	if err := co.ReleaseIP(vmName); err != nil {
		co.logger.Warn("Failed to release IP allocation",
			zap.String("vm_name", vmName),
			zap.Error(err))
	}

	// Delete VM metadata from KV - use DeleteTree for recursive deletion
	if _, err := co.client.KV().DeleteTree(fmt.Sprintf("vms/%s", vmName), nil); err != nil {
		return fmt.Errorf("failed to delete VM metadata from Consul: %w", err)
	}

	co.logger.Info("VM deregistered successfully", zap.String("vm_name", vmName))
	return nil
}

// AllocateIP allocates an IP address from the pool
func (co *ConsulOrchestrator) AllocateIP(vmName string) (string, error) {
	co.ipAllocMux.Lock()
	defer co.ipAllocMux.Unlock()

	co.logger.Info("Allocating IP for VM", zap.String("vm_name", vmName))

	// Get all allocated IPs from Consul
	allocations, err := co.getAllocatedIPs()
	if err != nil {
		return "", fmt.Errorf("failed to get allocated IPs: %w", err)
	}

	// Find next available IP
	ip, err := co.findNextAvailableIP(allocations)
	if err != nil {
		return "", fmt.Errorf("failed to find available IP: %w", err)
	}

	// Store allocation in Consul
	allocation := &IPAllocation{
		IP:        ip,
		VMName:    vmName,
		Allocated: time.Now(),
		InUse:     true,
	}

	data, err := json.Marshal(allocation)
	if err != nil {
		return "", fmt.Errorf("failed to marshal IP allocation: %w", err)
	}

	kvPair := &api.KVPair{
		Key:   fmt.Sprintf("ip-allocations/%s", ip),
		Value: data,
	}

	if _, err := co.client.KV().Put(kvPair, nil); err != nil {
		return "", fmt.Errorf("failed to store IP allocation: %w", err)
	}

	co.logger.Info("IP allocated successfully",
		zap.String("vm_name", vmName),
		zap.String("ip", ip))

	return ip, nil
}

// ReleaseIP releases an allocated IP address
func (co *ConsulOrchestrator) ReleaseIP(vmName string) error {
	co.ipAllocMux.Lock()
	defer co.ipAllocMux.Unlock()

	co.logger.Info("Releasing IP for VM", zap.String("vm_name", vmName))

	// Find the allocation for this VM
	allocations, err := co.getAllocatedIPs()
	if err != nil {
		return fmt.Errorf("failed to get allocated IPs: %w", err)
	}

	for ip, alloc := range allocations {
		if alloc.VMName == vmName {
			// Delete the allocation
			if _, err := co.client.KV().Delete(fmt.Sprintf("ip-allocations/%s", ip), nil); err != nil {
				return fmt.Errorf("failed to delete IP allocation: %w", err)
			}

			co.logger.Info("IP released successfully",
				zap.String("vm_name", vmName),
				zap.String("ip", ip))
			return nil
		}
	}

	return fmt.Errorf("no IP allocation found for VM %s", vmName)
}

// getAllocatedIPs retrieves all allocated IPs from Consul
func (co *ConsulOrchestrator) getAllocatedIPs() (map[string]*IPAllocation, error) {
	allocations := make(map[string]*IPAllocation)

	kvPairs, _, err := co.client.KV().List("ip-allocations/", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list IP allocations: %w", err)
	}

	for _, kvPair := range kvPairs {
		var alloc IPAllocation
		if err := json.Unmarshal(kvPair.Value, &alloc); err != nil {
			co.logger.Warn("Failed to unmarshal IP allocation",
				zap.String("key", kvPair.Key),
				zap.Error(err))
			continue
		}
		allocations[alloc.IP] = &alloc
	}

	return allocations, nil
}

// findNextAvailableIP finds the next available IP in the range
func (co *ConsulOrchestrator) findNextAvailableIP(allocations map[string]*IPAllocation) (string, error) {
	startIP := net.ParseIP(co.ipRange.Start)
	endIP := net.ParseIP(co.ipRange.End)

	if startIP == nil || endIP == nil {
		return "", fmt.Errorf("invalid IP range configuration")
	}

	// Convert to uint32 for easier iteration
	start := ipToUint32(startIP.To4())
	end := ipToUint32(endIP.To4())

	for i := start; i <= end; i++ {
		ip := uint32ToIP(i).String()

		// Check if IP is reserved
		isReserved := false
		for _, reserved := range co.ipRange.Reserved {
			if ip == reserved {
				isReserved = true
				break
			}
		}
		if isReserved {
			continue
		}

		// Check if IP is already allocated
		if _, allocated := allocations[ip]; !allocated {
			return ip, nil
		}
	}

	return "", fmt.Errorf("no available IPs in range %s-%s", co.ipRange.Start, co.ipRange.End)
}

// GetVMHealth checks the health status of a VM
func (co *ConsulOrchestrator) GetVMHealth(vmName string) (string, error) {
	serviceID := fmt.Sprintf("vm-%s", vmName)

	checks, err := co.client.Agent().Checks()
	if err != nil {
		return "", fmt.Errorf("failed to get health checks: %w", err)
	}

	checkID := fmt.Sprintf("%s-health", serviceID)
	if check, exists := checks[checkID]; exists {
		return check.Status, nil
	}

	return "unknown", nil
}

// ListVMs lists all registered VMs
func (co *ConsulOrchestrator) ListVMs() ([]*OrchestratedVM, error) {
	services, err := co.client.Agent().Services()
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	var vms []*OrchestratedVM
	for _, service := range services {
		// Filter for VM services
		if len(service.ID) > 3 && service.ID[:3] == "vm-" {
			// Get VM metadata from KV
			vmName := service.ID[3:] // Remove "vm-" prefix
			kvPair, _, err := co.client.KV().Get(fmt.Sprintf("vms/%s/metadata", vmName), nil)

			var meta map[string]string
			if err == nil && kvPair != nil {
				var kvData map[string]interface{}
				if err := json.Unmarshal(kvPair.Value, &kvData); err == nil {
					if m, ok := kvData["meta"].(map[string]interface{}); ok {
						meta = make(map[string]string)
						for k, v := range m {
							meta[k] = fmt.Sprintf("%v", v)
						}
					}
				}
			}

			// Get health status
			health, _ := co.GetVMHealth(vmName)

			vm := &OrchestratedVM{
				Name:            vmName,
				IPAddress:       service.Address,
				ConsulServiceID: service.ID,
				State:           "running", // Assume running if registered
				Health:          health,
				Meta:            meta,
			}

			vms = append(vms, vm)
		}
	}

	return vms, nil
}

// Helper functions for IP conversion
func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 + uint32(ip[1])<<16 + uint32(ip[2])<<8 + uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}