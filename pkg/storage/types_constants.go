package storage

// StorageState represents the state of a storage resource
type StorageState string

const (
	StorageStateActive    StorageState = "active"
	StorageStateInactive  StorageState = "inactive"
	StorageStateDegraded  StorageState = "degraded"
	StorageStateFailed    StorageState = "failed"
	StorageStateCreating  StorageState = "creating"
	StorageStateDeleting  StorageState = "deleting"
	StorageStateUnknown   StorageState = "unknown"
)

// HealthStatus represents health status of storage resources
type HealthStatus string

// Health status constants
const (
	HealthGood     HealthStatus = "good"
	HealthDegraded HealthStatus = "degraded"
	HealthCritical HealthStatus = "critical"
	HealthUnknown  HealthStatus = "unknown"
)

// DriverConfig represents driver-specific configuration
type DriverConfig map[string]interface{}