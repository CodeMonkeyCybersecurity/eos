package sizing

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PreflightCheck validates that the current system meets the requirements for the requested services
func PreflightCheck(rc *eos_io.RuntimeContext, services []ServiceType, workload WorkloadProfile) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting preflight hardware validation",
		zap.Any("services", services),
		zap.String("workload", workload.Name))

	// ASSESS - Get current system resources
	currentResources, err := getSystemResources(rc)
	if err != nil {
		return fmt.Errorf("failed to assess system resources: %w", err)
	}

	logger.Info("Current system resources",
		zap.Float64("cpu_cores", currentResources.CPU.Cores),
		zap.Float64("memory_gb", currentResources.Memory.GB),
		zap.Float64("disk_gb", currentResources.Disk.GB))

	// Calculate requirements for requested services
	calculator := NewCalculator(EnvironmentConfigs["production"], workload)

	// Add services to calculator
	for _, svcType := range services {
		_ = calculator.AddService(svcType)
	}

	result, err := calculator.Calculate(rc)
	if err != nil {
		return fmt.Errorf("failed to calculate resource requirements: %w", err)
	}

	logger.Info("Calculated resource requirements",
		zap.Float64("required_cpu_cores", result.TotalCPUCores),
		zap.Float64("required_memory_gb", result.TotalMemoryGB),
		zap.Float64("required_disk_gb", result.TotalDiskGB))

	// INTERVENE - Check if resources are sufficient
	var insufficientResources []string
	var warnings []string

	// CPU check
	if currentResources.CPU.Cores < result.TotalCPUCores {
		insufficientResources = append(insufficientResources,
			fmt.Sprintf("CPU: have %.1f cores, need %.1f cores",
				currentResources.CPU.Cores, result.TotalCPUCores))
	} else if currentResources.CPU.Cores < result.TotalCPUCores*1.2 {
		warnings = append(warnings,
			fmt.Sprintf("CPU: running close to capacity (%.1f/%.1f cores)",
				result.TotalCPUCores, currentResources.CPU.Cores))
	}

	// Memory check
	if currentResources.Memory.GB < result.TotalMemoryGB {
		insufficientResources = append(insufficientResources,
			fmt.Sprintf("Memory: have %.1f GB, need %.1f GB",
				currentResources.Memory.GB, result.TotalMemoryGB))
	} else if currentResources.Memory.GB < result.TotalMemoryGB*1.2 {
		warnings = append(warnings,
			fmt.Sprintf("Memory: running close to capacity (%.1f/%.1f GB)",
				result.TotalMemoryGB, currentResources.Memory.GB))
	}

	// Disk check
	if currentResources.Disk.GB < result.TotalDiskGB {
		insufficientResources = append(insufficientResources,
			fmt.Sprintf("Disk: have %.1f GB free, need %.1f GB",
				currentResources.Disk.GB, result.TotalDiskGB))
	} else if currentResources.Disk.GB < result.TotalDiskGB*1.5 {
		warnings = append(warnings,
			fmt.Sprintf("Disk: limited headroom (%.1f/%.1f GB free)",
				result.TotalDiskGB, currentResources.Disk.GB))
	}

	// Check for specific service requirements
	for _, svcReq := range result.Services {
		// Check for high-performance requirements
		if svcReq.Service.Type == ServiceTypeDatabase && currentResources.Disk.Type != "ssd" && currentResources.Disk.Type != "nvme" {
			warnings = append(warnings,
				fmt.Sprintf("Database performance: SSD or NVMe storage recommended (current: %s)",
					currentResources.Disk.Type))
		}

		// Check for specific CPU types
		if svcReq.Service.BaseRequirements.CPU.Type == "compute" && runtime.NumCPU() < 4 {
			warnings = append(warnings,
				"Compute-intensive workload on system with limited CPU cores")
		}
	}

	// EVALUATE - Handle insufficient resources
	if len(insufficientResources) > 0 {
		logger.Error("Insufficient system resources detected",
			zap.Strings("insufficient", insufficientResources))

		// Show detailed resource report
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt:  System Resource Check Failed")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: The following resources are insufficient:")
		for _, issue := range insufficientResources {
			logger.Info(fmt.Sprintf("terminal prompt:   • %s", issue))
		}
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Current System:")
		logger.Info(fmt.Sprintf("terminal prompt:   CPU:    %.1f cores", currentResources.CPU.Cores))
		logger.Info(fmt.Sprintf("terminal prompt:   Memory: %.1f GB", currentResources.Memory.GB))
		logger.Info(fmt.Sprintf("terminal prompt:   Disk:   %.1f GB free", currentResources.Disk.GB))
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Required for deployment:")
		logger.Info(fmt.Sprintf("terminal prompt:   CPU:    %.1f cores", result.TotalCPUCores))
		logger.Info(fmt.Sprintf("terminal prompt:   Memory: %.1f GB", result.TotalMemoryGB))
		logger.Info(fmt.Sprintf("terminal prompt:   Disk:   %.1f GB", result.TotalDiskGB))
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Would you like to proceed anyway? This may lead to performance issues. [y/N]: ")

		// Get user confirmation
		response, err := eos_io.ReadInput(rc)
		if err != nil {
			return fmt.Errorf("failed to read user input: %w", err)
		}

		response = strings.ToLower(strings.TrimSpace(response))
		if response != "y" && response != "yes" {
			return eos_err.NewUserError("deployment cancelled due to insufficient resources")
		}

		logger.Warn("User chose to proceed despite insufficient resources")
	}

	// Show warnings if any
	if len(warnings) > 0 {
		logger.Warn("Resource warnings detected", zap.Strings("warnings", warnings))
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Resource Warnings:")
		for _, warning := range warnings {
			logger.Info(fmt.Sprintf("terminal prompt:   • %s", warning))
		}
		logger.Info("terminal prompt: ")
	}

	// Add recommendations from sizing result
	if len(result.Recommendations) > 0 {
		logger.Info("terminal prompt:  Recommendations:")
		for _, rec := range result.Recommendations {
			logger.Info(fmt.Sprintf("terminal prompt:   • %s", rec))
		}
		logger.Info("terminal prompt: ")
	}

	logger.Info("Preflight checks completed successfully")
	return nil
}

// SystemResources represents the current system's available resources
type SystemResources struct {
	CPU    CPUInfo
	Memory MemoryInfo
	Disk   DiskInfo
}

// CPUInfo contains CPU information
type CPUInfo struct {
	Cores float64
	Model string
	Type  string // "general", "compute", etc.
}

// MemoryInfo contains memory information
type MemoryInfo struct {
	GB        float64
	Available float64
	Type      string // "standard", "high-performance"
}

// DiskInfo contains disk information
type DiskInfo struct {
	GB         float64
	Type       string // "ssd", "hdd", "nvme"
	MountPoint string
}

// getSystemResources retrieves current system resource information
func getSystemResources(rc *eos_io.RuntimeContext) (*SystemResources, error) {
	logger := otelzap.Ctx(rc.Ctx)
	resources := &SystemResources{}

	// Get CPU information
	cpuInfo, err := cpu.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU info: %w", err)
	}

	// Count logical CPUs
	resources.CPU.Cores = float64(runtime.NumCPU())

	// Determine CPU type based on model
	if len(cpuInfo) > 0 {
		resources.CPU.Model = cpuInfo[0].ModelName
		// Simple heuristic for CPU type
		if strings.Contains(strings.ToLower(resources.CPU.Model), "xeon") ||
			strings.Contains(strings.ToLower(resources.CPU.Model), "epyc") {
			resources.CPU.Type = "compute"
		} else {
			resources.CPU.Type = "general"
		}
	}

	// Get memory information
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, fmt.Errorf("failed to get memory info: %w", err)
	}

	resources.Memory.GB = float64(memInfo.Total) / (1024 * 1024 * 1024)
	resources.Memory.Available = float64(memInfo.Available) / (1024 * 1024 * 1024)
	resources.Memory.Type = "standard" // Could be enhanced with actual detection

	// Get disk information for root filesystem
	diskInfo, err := disk.Usage("/")
	if err != nil {
		return nil, fmt.Errorf("failed to get disk info: %w", err)
	}

	resources.Disk.GB = float64(diskInfo.Free) / (1024 * 1024 * 1024)
	resources.Disk.MountPoint = "/"

	// Determine disk type
	resources.Disk.Type = detectDiskType(rc)

	logger.Debug("System resources detected",
		zap.Any("cpu", resources.CPU),
		zap.Any("memory", resources.Memory),
		zap.Any("disk", resources.Disk))

	return resources, nil
}

// detectDiskType attempts to determine the type of storage (ssd/hdd/nvme)
func detectDiskType(rc *eos_io.RuntimeContext) string {
	logger := otelzap.Ctx(rc.Ctx)

	// Try to detect disk type using lsblk
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "lsblk",
		Args:    []string{"-o", "NAME,ROTA,TYPE", "-n"},
		Capture: true,
	})

	if err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[2] == "disk" {
				// ROTA=0 means SSD/NVMe, ROTA=1 means HDD
				if fields[1] == "0" {
					// Further check if it's NVMe
					if strings.HasPrefix(fields[0], "nvme") {
						return "nvme"
					}
					return "ssd"
				}
			}
		}
	}

	// Fallback: check for NVMe devices
	if _, err := os.Stat("/dev/nvme0n1"); err == nil {
		return "nvme"
	}

	// Default to HDD if can't determine
	logger.Debug("Could not determine disk type, defaulting to HDD")
	return "hdd"
}
