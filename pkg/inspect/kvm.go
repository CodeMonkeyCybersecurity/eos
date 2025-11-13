package inspect

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DiscoverKVM gathers KVM/Libvirt infrastructure information
func (i *Inspector) DiscoverKVM() (*KVMInfo, error) {
	logger := otelzap.Ctx(i.rc.Ctx)
	logger.Info(" Starting KVM/Libvirt discovery")

	// Check if virsh is installed
	if !i.commandExists("virsh") {
		return nil, fmt.Errorf("virsh command not found")
	}

	// Check if libvirtd is running
	if output, err := i.runCommand("systemctl", "is-active", "libvirtd"); err != nil || output != "active" {
		return nil, fmt.Errorf("libvirtd is not running")
	}

	info := &KVMInfo{}

	// Get libvirt version
	if output, err := i.runCommand("virsh", "version", "--daemon"); err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "library") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					info.LibvirtVersion = parts[len(parts)-1]
					logger.Info(" Libvirt version detected", zap.String("version", info.LibvirtVersion))
					break
				}
			}
		}
	}

	// Discover VMs
	if vms, err := i.discoverVMs(); err != nil {
		logger.Warn("Failed to discover VMs", zap.Error(err))
	} else {
		info.VMs = vms
		logger.Info(" Discovered VMs", zap.Int("count", len(vms)))
	}

	// Discover networks
	if networks, err := i.discoverKVMNetworks(); err != nil {
		logger.Warn("Failed to discover KVM networks", zap.Error(err))
	} else {
		info.Networks = networks
		logger.Info(" Discovered KVM networks", zap.Int("count", len(networks)))
	}

	// Discover storage pools
	if pools, err := i.discoverStoragePools(); err != nil {
		logger.Warn("Failed to discover storage pools", zap.Error(err))
	} else {
		info.StoragePools = pools
		logger.Info(" Discovered storage pools", zap.Int("count", len(pools)))
	}

	logger.Info(" KVM discovery completed")
	return info, nil
}

// discoverVMs discovers all KVM virtual machines
func (i *Inspector) discoverVMs() ([]KVMDomain, error) {
	var vms []KVMDomain

	// Get all VM names
	output, err := i.runCommand("virsh", "list", "--all", "--name")
	if err != nil {
		return nil, err
	}

	vmNames := strings.Split(strings.TrimSpace(output), "\n")
	for _, name := range vmNames {
		if name == "" {
			continue
		}

		vm := KVMDomain{
			Name: name,
		}

		// Get VM info
		if infoOutput, err := i.runCommand("virsh", "dominfo", name); err == nil {
			vm = i.parseVMInfo(vm, infoOutput)
		}

		// Get VM XML for detailed configuration
		if xmlOutput, err := i.runCommand("virsh", "dumpxml", name); err == nil {
			if details, err := i.parseVMXML(xmlOutput); err == nil {
				vm.OSType = details.OSType
				vm.Disks = details.Disks
				vm.Interfaces = details.Interfaces
			}
		}

		vms = append(vms, vm)
	}

	return vms, nil
}

// parseVMInfo parses virsh dominfo output
func (i *Inspector) parseVMInfo(vm KVMDomain, output string) KVMDomain {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "UUID":
			vm.UUID = value
		case "State":
			vm.State = value
		case "CPU(s)":
			if v, err := strconv.Atoi(value); err == nil {
				vm.CPUs = v
			}
		case "Max memory":
			vm.Memory = value
		case "Used memory":
			// Update if we want current vs max
			if vm.Memory == "" {
				vm.Memory = value
			}
		}
	}
	return vm
}

// VM XML structures for parsing
type vmXML struct {
	XMLName xml.Name `xml:"domain"`
	OS      struct {
		Type struct {
			Arch    string `xml:"arch,attr"`
			Machine string `xml:"machine,attr"`
			Value   string `xml:",chardata"`
		} `xml:"type"`
	} `xml:"os"`
	Devices struct {
		Disks []struct {
			Type   string `xml:"type,attr"`
			Device string `xml:"device,attr"`
			Driver struct {
				Type string `xml:"type,attr"`
			} `xml:"driver"`
			Source struct {
				File string `xml:"file,attr"`
				Dev  string `xml:"dev,attr"`
			} `xml:"source"`
			Target struct {
				Dev string `xml:"dev,attr"`
				Bus string `xml:"bus,attr"`
			} `xml:"target"`
		} `xml:"disk"`
		Interfaces []struct {
			Type string `xml:"type,attr"`
			MAC  struct {
				Address string `xml:"address,attr"`
			} `xml:"mac"`
			Source struct {
				Network string `xml:"network,attr"`
				Bridge  string `xml:"bridge,attr"`
			} `xml:"source"`
			Model struct {
				Type string `xml:"type,attr"`
			} `xml:"model"`
		} `xml:"interface"`
	} `xml:"devices"`
}

// parseVMXML parses VM XML configuration
func (i *Inspector) parseVMXML(xmlData string) (*KVMDomain, error) {
	// SECURITY P0 #2: Use xml.Decoder to prevent XXE attacks
	decoder := xml.NewDecoder(strings.NewReader(xmlData))
	decoder.Entity = make(map[string]string) // Disable external entities

	var vmData vmXML
	if err := decoder.Decode(&vmData); err != nil {
		return nil, err
	}

	vm := &KVMDomain{
		OSType: fmt.Sprintf("%s/%s", vmData.OS.Type.Value, vmData.OS.Type.Arch),
	}

	// Parse disks
	for _, disk := range vmData.Devices.Disks {
		if disk.Device != "disk" {
			continue
		}

		d := KVMDisk{
			Device: disk.Target.Dev,
			Bus:    disk.Target.Bus,
			Format: disk.Driver.Type,
		}

		if disk.Source.File != "" {
			d.Path = disk.Source.File
			// Try to get disk size
			if output, err := i.runCommand("qemu-img", "info", d.Path, "--output=json"); err == nil {
				if size := extractDiskSize(output); size != "" {
					d.Size = size
				}
			}
		} else if disk.Source.Dev != "" {
			d.Path = disk.Source.Dev
		}

		vm.Disks = append(vm.Disks, d)
	}

	// Parse interfaces
	for _, iface := range vmData.Devices.Interfaces {
		intf := KVMInterface{
			Type:  iface.Type,
			MAC:   iface.MAC.Address,
			Model: iface.Model.Type,
		}

		if iface.Source.Network != "" {
			intf.Source = iface.Source.Network
		} else if iface.Source.Bridge != "" {
			intf.Source = iface.Source.Bridge
		}

		vm.Interfaces = append(vm.Interfaces, intf)
	}

	return vm, nil
}

// extractDiskSize extracts disk size from qemu-img info JSON output
func extractDiskSize(output string) string {
	// Simple extraction - could be improved with proper JSON parsing
	re := regexp.MustCompile(`"virtual-size":\s*(\d+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) > 1 {
		if bytes, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
			// Convert bytes to human-readable
			return formatBytes(bytes)
		}
	}
	return ""
}

// discoverKVMNetworks discovers libvirt networks
func (i *Inspector) discoverKVMNetworks() ([]KVMNetwork, error) {
	var networks []KVMNetwork

	// Get all network names
	output, err := i.runCommand("virsh", "net-list", "--all", "--name")
	if err != nil {
		return nil, err
	}

	netNames := strings.Split(strings.TrimSpace(output), "\n")
	for _, name := range netNames {
		if name == "" {
			continue
		}

		network := KVMNetwork{
			Name: name,
		}

		// Get network info
		if infoOutput, err := i.runCommand("virsh", "net-info", name); err == nil {
			lines := strings.Split(infoOutput, "\n")
			for _, line := range lines {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) != 2 {
					continue
				}

				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch key {
				case "UUID":
					network.UUID = value
				case "Active":
					network.Active = value == "yes"
				case "Persistent":
					network.Persistent = value == "yes"
				case "Bridge":
					network.Bridge = value
				}
			}
		}

		networks = append(networks, network)
	}

	return networks, nil
}

// discoverStoragePools discovers libvirt storage pools
func (i *Inspector) discoverStoragePools() ([]KVMPool, error) {
	var pools []KVMPool

	// Get all pool names
	output, err := i.runCommand("virsh", "pool-list", "--all", "--name")
	if err != nil {
		return nil, err
	}

	poolNames := strings.Split(strings.TrimSpace(output), "\n")
	for _, name := range poolNames {
		if name == "" {
			continue
		}

		pool := KVMPool{
			Name: name,
		}

		// Get pool info
		if infoOutput, err := i.runCommand("virsh", "pool-info", name); err == nil {
			lines := strings.Split(infoOutput, "\n")
			for _, line := range lines {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) != 2 {
					continue
				}

				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch key {
				case "UUID":
					pool.UUID = value
				case "State":
					pool.State = value
				case "Capacity":
					pool.Capacity = value
				case "Allocation":
					pool.Allocation = value
				case "Available":
					pool.Available = value
				}
			}
		}

		// Get pool target path
		if xmlOutput, err := i.runCommand("virsh", "pool-dumpxml", name); err == nil {
			// Simple extraction of target path
			re := regexp.MustCompile(`<path>([^<]+)</path>`)
			matches := re.FindStringSubmatch(xmlOutput)
			if len(matches) > 1 {
				pool.Path = matches[1]
			}
		}

		pools = append(pools, pool)
	}

	return pools, nil
}

// formatBytes converts bytes to human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
