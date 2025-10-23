//go:build darwin
// +build darwin

// pkg/kvm/types_stub_darwin.go
// Type stubs for macOS - must match real implementations

package kvm

// Backup types
type OrchestratorOptions struct{}
type VMBackupOrchestrator struct{}
type BatchBackupSummary struct{}
type BackupManager struct{}
type VMBackupResult struct{}
type SnapshotBackupResult struct{}

// Consul orchestration types
type ConsulAutoRegisterConfig struct{}
type ConsulOrchestrator struct{}
type IPRange struct{}
type VMRegistration struct{}
type HealthCheck struct{}
type OrchestratedVM struct{}
type IPAllocation struct{}

// Nomad orchestration types
type NomadOrchestrator struct{}
type NomadVMJob struct{}
type Constraint struct{}
type OrchestratedVMManager struct{}

// VM Pool types
type VMPool struct{}
type VMPoolManager struct{}
type PoolMetrics struct{}
type ScalingRules struct{}

// Disk management types
type Manager struct{}
type Assessment struct{}
type Risk struct{}
type RiskLevel string
type ResizeRequest struct{}
type Transaction struct{}
type StepResult struct{}
type SizeChange struct{}
type TransactionLog struct{}
type GuestManager struct{}

// Snapshot types
type SnapshotConfig struct{}
type SnapshotInfo struct{}
type SnapshotManager struct{}

// VM types
type VMInfo struct{}
type VMEntry struct{}
type DiskInfo struct{}

// Config types
type CloudInitConfig struct{}
type SecureVMConfig struct{}
type SecurityLevel string
type RestartConfig struct{}
type PackageUpgradeConfig struct{}
type PackageUpgradeResult struct{}
type UpgradeAndRebootConfig struct{}
type UpgradeAndRebootResult struct{}
type GuestExecConfig struct{}
type GuestExecResult struct{}
type GuestAgentAddConfig struct{}
type GuestAgentAddResult struct{}
type AddOperationConfig struct{}
type EnableOperationConfig struct{}
type RestartOperationConfig struct{}
type BackupFilter struct{}
type SimpleVMConfig struct{}
type TemplateContext struct{}
type OutputConfig struct{}

// KVMManager stub type
type KVMManager struct{}
