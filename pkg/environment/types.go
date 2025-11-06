// pkg/environment/types.go

package environment

// EnvironmentScale represents the scale category of the deployment
type EnvironmentScale string

const (
	ScaleSingle      EnvironmentScale = "single"      // 1 machine
	ScaleSmall       EnvironmentScale = "small"       // 2-3 machines
	ScaleMedium      EnvironmentScale = "medium"      // 4-6 machines
	ScaleDistributed EnvironmentScale = "distributed" // 7+ machines
)

// GetScale returns the scale category based on machine count
func (e *Environment) GetScale() EnvironmentScale {
	switch {
	case e.MachineCount == 1:
		return ScaleSingle
	case e.MachineCount <= 3:
		return ScaleSmall
	case e.MachineCount <= 6:
		return ScaleMedium
	default:
		return ScaleDistributed
	}
}

// StorageProfile contains storage-specific configuration for an environment
type StorageProfile struct {
	Scale              EnvironmentScale
	DefaultThresholds  ThresholdConfig
	BackupStrategy     string
	CleanupPolicy      string
	MonitoringInterval string
}

// ThresholdConfig contains storage threshold percentages
type ThresholdConfig struct {
	Warning   float64
	Compress  float64
	Cleanup   float64
	Degraded  float64
	Emergency float64
	Critical  float64
}

// GetStorageProfile returns the appropriate storage profile for the environment
func (e *Environment) GetStorageProfile() StorageProfile {
	scale := e.GetScale()

	profiles := map[EnvironmentScale]StorageProfile{
		ScaleSingle: {
			Scale: ScaleSingle,
			DefaultThresholds: ThresholdConfig{
				Warning:   60,
				Compress:  70,
				Cleanup:   75,
				Degraded:  80,
				Emergency: 85,
				Critical:  90,
			},
			BackupStrategy:     "local",
			CleanupPolicy:      "aggressive",
			MonitoringInterval: "5m",
		},
		ScaleSmall: {
			Scale: ScaleSmall,
			DefaultThresholds: ThresholdConfig{
				Warning:   65,
				Compress:  75,
				Cleanup:   80,
				Degraded:  85,
				Emergency: 90,
				Critical:  95,
			},
			BackupStrategy:     "distributed",
			CleanupPolicy:      "balanced",
			MonitoringInterval: "5m",
		},
		ScaleMedium: {
			Scale: ScaleMedium,
			DefaultThresholds: ThresholdConfig{
				Warning:   70,
				Compress:  80,
				Cleanup:   85,
				Degraded:  90,
				Emergency: 93,
				Critical:  95,
			},
			BackupStrategy:     "distributed",
			CleanupPolicy:      "conservative",
			MonitoringInterval: "3m",
		},
		ScaleDistributed: {
			Scale: ScaleDistributed,
			DefaultThresholds: ThresholdConfig{
				Warning:   70,
				Compress:  80,
				Cleanup:   85,
				Degraded:  90,
				Emergency: 93,
				Critical:  95,
			},
			BackupStrategy:     "distributed",
			CleanupPolicy:      "conservative",
			MonitoringInterval: "1m",
		},
	}

	return profiles[scale]
}
