package orchestration

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VMPoolManager manages pools of VMs
type VMPoolManager struct {
	orchestrator *OrchestratedVMManager
	pools        map[string]*VMPool
	poolsMux     sync.RWMutex
	logger       otelzap.LoggerWithCtx
	rc           *eos_io.RuntimeContext
	stopChan     chan struct{}
	wg           sync.WaitGroup
}

// NewVMPoolManager creates a new VM pool manager
func NewVMPoolManager(rc *eos_io.RuntimeContext, consulAddr, nomadAddr string) (*VMPoolManager, error) {
	logger := otelzap.Ctx(rc.Ctx)

	orchestrator, err := NewOrchestratedVMManager(rc, consulAddr, nomadAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create orchestrated VM manager: %w", err)
	}

	return &VMPoolManager{
		orchestrator: orchestrator,
		pools:        make(map[string]*VMPool),
		logger:       logger,
		rc:           rc,
		stopChan:     make(chan struct{}),
	}, nil
}

// CreatePool creates a new VM pool
func (pm *VMPoolManager) CreatePool(pool *VMPool) error {
	pm.poolsMux.Lock()
	defer pm.poolsMux.Unlock()

	if _, exists := pm.pools[pool.Name]; exists {
		return fmt.Errorf("pool already exists: %s", pool.Name)
	}

	pm.logger.Info("Creating VM pool",
		zap.String("pool_name", pool.Name),
		zap.Int("min_size", pool.MinSize),
		zap.Int("max_size", pool.MaxSize))

	// Initialize the pool
	pool.CurrentSize = 0
	pm.pools[pool.Name] = pool

	// Create initial VMs to meet minimum size
	for i := 0; i < pool.MinSize; i++ {
		vmName := fmt.Sprintf("%s-%03d", pool.Name, i+1)
		if err := pm.createPoolVM(pool, vmName); err != nil {
			pm.logger.Error("Failed to create pool VM",
				zap.String("vm_name", vmName),
				zap.Error(err))
			// Continue creating other VMs
		} else {
			pool.CurrentSize++
		}
	}

	// Create Nomad job for pool management if Nomad is available
	if err := pm.orchestrator.nomad.CreateVMPoolJob(pool); err != nil {
		pm.logger.Warn("Failed to create Nomad job for pool",
			zap.String("pool_name", pool.Name),
			zap.Error(err))
	}

	// Start monitoring if scaling rules are defined
	if pool.ScalingRules != nil {
		pm.wg.Add(1)
		go pm.monitorPool(pool)
	}

	pm.logger.Info("VM pool created successfully",
		zap.String("pool_name", pool.Name),
		zap.Int("current_size", pool.CurrentSize))

	return nil
}

// createPoolVM creates a VM for a pool
func (pm *VMPoolManager) createPoolVM(pool *VMPool, vmName string) error {
	pm.logger.Info("Creating VM for pool",
		zap.String("pool_name", pool.Name),
		zap.String("vm_name", vmName))

	// Add pool tags
	if err := pm.orchestrator.CreateOrchestratedVM(vmName, true); err != nil {
		return fmt.Errorf("failed to create VM: %w", err)
	}

	// Update Consul metadata with pool information
	kvData := map[string]interface{}{
		"pool_name": pool.Name,
		"pool_tags": pool.Tags,
		"created":   time.Now().Unix(),
	}

	if err := pm.updateVMPoolMetadata(vmName, kvData); err != nil {
		pm.logger.Warn("Failed to update VM pool metadata",
			zap.String("vm_name", vmName),
			zap.Error(err))
	}

	return nil
}

// updateVMPoolMetadata updates VM metadata in Consul
func (pm *VMPoolManager) updateVMPoolMetadata(vmName string, metadata map[string]interface{}) error {
	// This would update the VM's metadata in Consul KV store
	// For now, log the intent
	pm.logger.Debug("Would update VM pool metadata",
		zap.String("vm_name", vmName),
		zap.Any("metadata", metadata))
	return nil
}

// ScalePool scales a pool to a target size
func (pm *VMPoolManager) ScalePool(poolName string, targetSize int) error {
	pm.poolsMux.Lock()
	defer pm.poolsMux.Unlock()

	pool, exists := pm.pools[poolName]
	if !exists {
		return fmt.Errorf("pool not found: %s", poolName)
	}

	// Validate target size
	if targetSize < pool.MinSize {
		return fmt.Errorf("target size %d is below minimum %d", targetSize, pool.MinSize)
	}
	if targetSize > pool.MaxSize {
		return fmt.Errorf("target size %d exceeds maximum %d", targetSize, pool.MaxSize)
	}

	pm.logger.Info("Scaling pool",
		zap.String("pool_name", poolName),
		zap.Int("current_size", pool.CurrentSize),
		zap.Int("target_size", targetSize))

	if targetSize > pool.CurrentSize {
		// Scale up
		for i := pool.CurrentSize; i < targetSize; i++ {
			vmName := fmt.Sprintf("%s-%03d", pool.Name, i+1)
			if err := pm.createPoolVM(pool, vmName); err != nil {
				pm.logger.Error("Failed to create VM during scale up",
					zap.String("vm_name", vmName),
					zap.Error(err))
				return err
			}
			pool.CurrentSize++
		}
	} else if targetSize < pool.CurrentSize {
		// Scale down
		for i := pool.CurrentSize; i > targetSize; i-- {
			vmName := fmt.Sprintf("%s-%03d", pool.Name, i)
			if err := pm.orchestrator.DestroyOrchestratedVM(vmName); err != nil {
				pm.logger.Error("Failed to destroy VM during scale down",
					zap.String("vm_name", vmName),
					zap.Error(err))
				return err
			}
			pool.CurrentSize--
		}
	}

	pm.logger.Info("Pool scaled successfully",
		zap.String("pool_name", poolName),
		zap.Int("new_size", pool.CurrentSize))

	return nil
}

// monitorPool monitors a pool and applies auto-scaling
func (pm *VMPoolManager) monitorPool(pool *VMPool) {
	defer pm.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	lastScaleTime := time.Now()

	for {
		select {
		case <-pm.stopChan:
			return
		case <-ticker.C:
			// Check if cooldown period has passed
			if time.Since(lastScaleTime) < pool.ScalingRules.CooldownPeriod {
				continue
			}

			// Get pool metrics
			metrics, err := pm.getPoolMetrics(pool.Name)
			if err != nil {
				pm.logger.Warn("Failed to get pool metrics",
					zap.String("pool_name", pool.Name),
					zap.Error(err))
				continue
			}

			// Apply scaling rules
			shouldScale := false
			newSize := pool.CurrentSize

			if metrics.AvgCPU > pool.ScalingRules.CPUThresholdUp ||
				metrics.AvgMemory > pool.ScalingRules.MemThresholdUp {
				// Scale up
				newSize = pool.CurrentSize + pool.ScalingRules.ScaleUpIncrement
				if newSize > pool.MaxSize {
					newSize = pool.MaxSize
				}
				shouldScale = true
			} else if metrics.AvgCPU < pool.ScalingRules.CPUThresholdDown &&
				metrics.AvgMemory < pool.ScalingRules.MemThresholdDown {
				// Scale down
				newSize = pool.CurrentSize - pool.ScalingRules.ScaleDownDecrement
				if newSize < pool.MinSize {
					newSize = pool.MinSize
				}
				shouldScale = true
			}

			if shouldScale && newSize != pool.CurrentSize {
				pm.logger.Info("Auto-scaling pool",
					zap.String("pool_name", pool.Name),
					zap.Int("current_size", pool.CurrentSize),
					zap.Int("new_size", newSize),
					zap.Float64("avg_cpu", metrics.AvgCPU),
					zap.Float64("avg_memory", metrics.AvgMemory))

				if err := pm.ScalePool(pool.Name, newSize); err != nil {
					pm.logger.Error("Auto-scaling failed",
						zap.String("pool_name", pool.Name),
						zap.Error(err))
				} else {
					lastScaleTime = time.Now()
				}
			}
		}
	}
}

// PoolMetrics represents metrics for a VM pool
type PoolMetrics struct {
	AvgCPU    float64
	AvgMemory float64
	VMCount   int
}

// getPoolMetrics retrieves metrics for a pool
func (pm *VMPoolManager) getPoolMetrics(poolName string) (*PoolMetrics, error) {
	// This is a simplified implementation
	// In production, you would query actual metrics from monitoring systems

	metrics := &PoolMetrics{
		VMCount: 0,
		AvgCPU:  0,
		AvgMemory: 0,
	}

	// Get all VMs in the pool
	vms, err := pm.orchestrator.ListOrchestratedVMs()
	if err != nil {
		return nil, err
	}

	var totalCPU, totalMem float64
	count := 0

	for _, vm := range vms {
		if strings.HasPrefix(vm.Name, poolName+"-") {
			// Get VM metrics (simplified - would use actual monitoring)
			cpu, mem := pm.getVMMetrics(vm.Name)
			totalCPU += cpu
			totalMem += mem
			count++
		}
	}

	if count > 0 {
		metrics.VMCount = count
		metrics.AvgCPU = totalCPU / float64(count)
		metrics.AvgMemory = totalMem / float64(count)
	}

	return metrics, nil
}

// getVMMetrics gets CPU and memory usage for a VM
func (pm *VMPoolManager) getVMMetrics(vmName string) (cpu, memory float64) {
	// Simplified implementation - would query actual metrics
	// For now, return mock values

	// Try to get actual metrics using virsh
	cmd := exec.Command("virsh", "domstats", vmName, "--cpu-total", "--balloon")
	output, err := cmd.Output()
	if err != nil {
		// Return default values if command fails
		return 25.0, 50.0
	}

	// Parse output (simplified)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "cpu.time=") {
			// Parse CPU usage (simplified)
			cpu = 30.0 // Placeholder
		}
		if strings.Contains(line, "balloon.current=") {
			// Parse memory usage (simplified)
			memory = 60.0 // Placeholder
		}
	}

	return cpu, memory
}

// DeletePool deletes a VM pool
func (pm *VMPoolManager) DeletePool(poolName string) error {
	pm.poolsMux.Lock()
	defer pm.poolsMux.Unlock()

	pool, exists := pm.pools[poolName]
	if !exists {
		return fmt.Errorf("pool not found: %s", poolName)
	}

	pm.logger.Info("Deleting VM pool",
		zap.String("pool_name", poolName),
		zap.Int("current_size", pool.CurrentSize))

	// Destroy all VMs in the pool
	for i := 1; i <= pool.CurrentSize; i++ {
		vmName := fmt.Sprintf("%s-%03d", pool.Name, i)
		if err := pm.orchestrator.DestroyOrchestratedVM(vmName); err != nil {
			pm.logger.Error("Failed to destroy pool VM",
				zap.String("vm_name", vmName),
				zap.Error(err))
		}
	}

	// Delete Nomad job
	jobID := fmt.Sprintf("vm-pool-%s", poolName)
	if err := pm.orchestrator.nomad.DeleteVMJob(jobID); err != nil {
		pm.logger.Warn("Failed to delete Nomad job for pool",
			zap.String("pool_name", poolName),
			zap.Error(err))
	}

	// Remove from pools map
	delete(pm.pools, poolName)

	pm.logger.Info("VM pool deleted successfully",
		zap.String("pool_name", poolName))

	return nil
}

// ListPools lists all VM pools
func (pm *VMPoolManager) ListPools() []*VMPool {
	pm.poolsMux.RLock()
	defer pm.poolsMux.RUnlock()

	pools := make([]*VMPool, 0, len(pm.pools))
	for _, pool := range pm.pools {
		pools = append(pools, pool)
	}

	return pools
}

// GetPool retrieves a specific pool
func (pm *VMPoolManager) GetPool(poolName string) (*VMPool, error) {
	pm.poolsMux.RLock()
	defer pm.poolsMux.RUnlock()

	pool, exists := pm.pools[poolName]
	if !exists {
		return nil, fmt.Errorf("pool not found: %s", poolName)
	}

	return pool, nil
}

// Stop stops the pool manager
func (pm *VMPoolManager) Stop() {
	close(pm.stopChan)
	pm.wg.Wait()
}