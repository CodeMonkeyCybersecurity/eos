package boundary

import "time"

// Config holds boundary configuration
type Config struct {
	// Controller configuration
	DatabaseURL      string
	PublicClusterAddr string
	PublicAddr       string
	
	// Worker configuration
	InitialUpstreams []string
	PublicProxyAddr  string
	
	// Common configuration
	ListenerAddress  string
	TLSDisable      bool
	TLSCertFile     string
	TLSKeyFile      string
	
	// KMS configuration
	KMSType        string
	KMSKeyID       string
	KMSRegion      string
	
	// Installation options
	Version        string
	Role           string // "controller", "worker", or "dev" (combined)
	ClusterName    string
}

// Status represents the current Boundary installation status
type Status struct {
	Installed      bool
	Running        bool
	Failed         bool
	Version        string
	Role           string
	ServiceStatus  string
	ClusterMembers int
	LastError      string
	ConfigValid    bool
	DatabaseConnected bool
}

// CreateOptions represents options for creating a Boundary deployment
type CreateOptions struct {
	Target      string
	Config      *Config
	Force       bool
	Clean       bool
	Test        bool
	StreamOutput bool
	Timeout     time.Duration
}

// DeleteOptions represents options for deleting a Boundary deployment
type DeleteOptions struct {
	Target      string
	ClusterName string
	KeepData    bool
	KeepConfig  bool
	KeepUser    bool
	Force       bool
	Test        bool
	StreamOutput bool
	Timeout     time.Duration
}

// StatusOptions represents options for checking Boundary status
type StatusOptions struct {
	Target      string
	ClusterName string
	Detailed    bool
}

// StatusResult represents the status of Boundary across minions
type StatusResult struct {
	Minions map[string]MinionStatus
}

// MinionStatus represents Boundary status on a single minion
type MinionStatus struct {
	Minion     string
	Status     Status
	Output     string
	ConfigFile string
}