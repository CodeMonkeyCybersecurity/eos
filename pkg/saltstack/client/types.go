// pkg/salt/client/types.go
package client

import (
	"context"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// SaltClient defines the interface for interacting with Salt HTTP API
type SaltClient interface {
	// Authentication
	Login(ctx context.Context, credentials *Credentials) (*AuthResponse, error)
	Logout(ctx context.Context) error
	RefreshToken(ctx context.Context) error
	ValidateConnection(ctx context.Context) error

	// Execution
	RunCommand(ctx context.Context, req *CommandRequest) (*CommandResponse, error)
	RunState(ctx context.Context, req *StateRequest) (*StateResponse, error)
	RunOrchestrate(ctx context.Context, req *OrchestrationRequest) (*OrchestrationResponse, error)

	// Job Management
	GetJob(ctx context.Context, jobID string) (*JobResult, error)
	ListJobs(ctx context.Context, opts *JobListOptions) (*JobList, error)
	KillJob(ctx context.Context, jobID string) error

	// Minion Management
	ListMinions(ctx context.Context, opts *MinionListOptions) (*MinionList, error)
	GetMinionInfo(ctx context.Context, minionID string) (*MinionInfo, error)
	AcceptKey(ctx context.Context, minionID string) error
	RejectKey(ctx context.Context, minionID string) error
	DeleteKey(ctx context.Context, minionID string) error

	// Pillar Data
	GetPillar(ctx context.Context, minionID string, key string) (*PillarData, error)
	SetPillar(ctx context.Context, minionID string, key string, data interface{}) error
	RefreshPillar(ctx context.Context, minionID string) error

	// State Management
	GetState(ctx context.Context, req *StateInfoRequest) (*StateInfo, error)
	TestState(ctx context.Context, req *StateRequest) (*StateResponse, error)
	ApplyHighstate(ctx context.Context, minionID string) (*StateResponse, error)

	// File Management
	ListFiles(ctx context.Context, path string, env string) (*FileList, error)
	GetFile(ctx context.Context, path string, env string) (*FileContent, error)
	WriteFile(ctx context.Context, path string, env string, content []byte) error

	// Grains
	GetGrains(ctx context.Context, minionID string) (*GrainsData, error)
	SetGrain(ctx context.Context, minionID string, key string, value interface{}) error
	
	// Health and Status
	Ping(ctx context.Context, minionID string) (*PingResponse, error)
	GetStatus(ctx context.Context) (*SaltStatus, error)
}

// Credentials for Salt API authentication
type Credentials struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Eauth      string `json:"eauth"` // Authentication backend (pam, ldap, etc.)
	TokenTTL   int    `json:"token_ttl,omitempty"`
}

// AuthResponse contains authentication response
type AuthResponse struct {
	Token     string            `json:"token"`
	Start     float64           `json:"start"`
	Expire    float64           `json:"expire"`
	User      string            `json:"user"`
	Eauth     string            `json:"eauth"`
	Perms     []string          `json:"perms"`
	Return    []map[string]interface{} `json:"return"`
}

// CommandRequest for executing Salt commands
type CommandRequest struct {
	Client    string      `json:"client"`    // local, local_async, runner, wheel
	Target    string      `json:"tgt"`       // Target minions
	Function  string      `json:"fun"`       // Function to execute
	Args      []string    `json:"arg,omitempty"`
	Kwargs    map[string]interface{} `json:"kwarg,omitempty"`
	TargetType string     `json:"tgt_type,omitempty"` // glob, pcre, list, grain, etc.
	Timeout   int         `json:"timeout,omitempty"`
	BatchSize string      `json:"batch,omitempty"`
}

// CommandResponse from Salt command execution
type CommandResponse struct {
	Return []map[string]interface{} `json:"return"`
	JobID  string                   `json:"jid,omitempty"`
	Tag    string                   `json:"tag,omitempty"`
}

// StateRequest for Salt state operations
type StateRequest struct {
	Client     string                 `json:"client"`
	Target     string                 `json:"tgt"`
	Function   string                 `json:"fun"`
	Args       []string               `json:"arg,omitempty"`
	TargetType string                 `json:"tgt_type,omitempty"`
	Pillar     map[string]interface{} `json:"pillar,omitempty"`
	Test       bool                   `json:"test,omitempty"`
	Concurrent bool                   `json:"concurrent,omitempty"`
}

// StateResponse from Salt state execution
type StateResponse struct {
	Return []map[string]*StateResult `json:"return"`
	JobID  string                    `json:"jid,omitempty"`
}

// StateResult represents individual state execution result
type StateResult struct {
	Name     string                 `json:"name"`
	Changes  map[string]interface{} `json:"changes"`
	Result   *bool                  `json:"result"` // pointer to handle null
	Comment  string                 `json:"comment"`
	StartTime string                `json:"start_time"`
	Duration float64                `json:"duration"`
	RunNum   int                    `json:"__run_num__"`
	SLS      string                 `json:"__sls__"`
	ID       string                 `json:"__id__"`
}

// OrchestrationRequest for Salt orchestration
type OrchestrationRequest struct {
	Client   string                 `json:"client"`
	Function string                 `json:"fun"`
	Mods     []string               `json:"mods,omitempty"`
	Pillar   map[string]interface{} `json:"pillar,omitempty"`
	Kwargs   map[string]interface{} `json:"kwarg,omitempty"`
}

// OrchestrationResponse from orchestration execution
type OrchestrationResponse struct {
	Return []map[string]*OrchestrationResult `json:"return"`
	JobID  string                           `json:"jid,omitempty"`
}

// OrchestrationResult represents orchestration step result
type OrchestrationResult struct {
	Name     string                 `json:"name"`
	Result   bool                   `json:"result"`
	Comment  string                 `json:"comment"`
	Changes  map[string]interface{} `json:"changes"`
	Duration float64                `json:"duration"`
	Data     map[string]interface{} `json:"data,omitempty"`
}

// JobResult represents Salt job execution result
type JobResult struct {
	JobID     string                           `json:"jid"`
	Function  string                           `json:"fun"`
	Target    string                           `json:"tgt"`
	User      string                           `json:"user"`
	StartTime string                           `json:"start_time"`
	Return    map[string]interface{}           `json:"return"`
	Minions   []string                         `json:"minions"`
	Missing   []string                         `json:"missing,omitempty"`
	Result    map[string]map[string]interface{} `json:"result,omitempty"`
}

// JobListOptions for filtering job listings
type JobListOptions struct {
	SearchFunction string    `json:"search_function,omitempty"`
	SearchTarget   string    `json:"search_target,omitempty"`
	SearchJobID    string    `json:"search_jid,omitempty"`
	StartTime      *time.Time `json:"start_time,omitempty"`
	EndTime        *time.Time `json:"end_time,omitempty"`
	Limit          int       `json:"limit,omitempty"`
}

// JobList contains multiple job results
type JobList struct {
	Jobs []JobResult `json:"jobs"`
}

// MinionListOptions for filtering minion listings
type MinionListOptions struct {
	Status   string `json:"status,omitempty"`   // up, down
	Glob     string `json:"glob,omitempty"`
	GrainKey string `json:"grain_key,omitempty"`
	GrainValue string `json:"grain_value,omitempty"`
}

// MinionList contains minion information
type MinionList struct {
	Minions []MinionInfo `json:"minions"`
}

// MinionInfo represents minion details
type MinionInfo struct {
	ID         string                 `json:"id"`
	LastSeen   time.Time              `json:"last_seen"`
	Status     string                 `json:"status"`
	Grains     map[string]interface{} `json:"grains,omitempty"`
	Pillar     map[string]interface{} `json:"pillar,omitempty"`
	Version    string                 `json:"version,omitempty"`
	OS         string                 `json:"os,omitempty"`
	OSVersion  string                 `json:"os_version,omitempty"`
	IPAddress  string                 `json:"ip_address,omitempty"`
}

// PillarData represents pillar information
type PillarData struct {
	MinionID string                 `json:"minion_id"`
	Data     map[string]interface{} `json:"data"`
}

// StateInfoRequest for querying state information
type StateInfoRequest struct {
	State    string `json:"state"`
	MinionID string `json:"minion_id,omitempty"`
}

// StateInfo contains state module information
type StateInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Functions   []string `json:"functions"`
	Examples    []string `json:"examples,omitempty"`
}

// FileList represents file system listing
type FileList struct {
	Files []FileInfo `json:"files"`
}

// FileInfo represents file metadata
type FileInfo struct {
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	Mode     string    `json:"mode"`
	ModTime  time.Time `json:"mod_time"`
	IsDir    bool      `json:"is_dir"`
	Checksum string    `json:"checksum,omitempty"`
}

// FileContent represents file content
type FileContent struct {
	Path    string `json:"path"`
	Content []byte `json:"content"`
	Mode    string `json:"mode"`
	Size    int64  `json:"size"`
}

// GrainsData represents minion grains
type GrainsData struct {
	MinionID string                 `json:"minion_id"`
	Grains   map[string]interface{} `json:"grains"`
}

// PingResponse from minion ping
type PingResponse struct {
	MinionID string `json:"minion_id"`
	Success  bool   `json:"success"`
	Time     string `json:"time"`
}

// SaltStatus represents Salt master status
type SaltStatus struct {
	Version      string              `json:"version"`
	Uptime       time.Duration       `json:"uptime"`
	MinionsUp    int                 `json:"minions_up"`
	MinionsDown  int                 `json:"minions_down"`
	JobsActive   int                 `json:"jobs_active"`
	JobsComplete int                 `json:"jobs_complete"`
	LoadAverage  []float64           `json:"load_average"`
	Memory       *MemoryStats        `json:"memory,omitempty"`
	Events       *EventStats         `json:"events,omitempty"`
}

// MemoryStats represents memory usage statistics
type MemoryStats struct {
	Used      int64   `json:"used"`
	Available int64   `json:"available"`
	Total     int64   `json:"total"`
	Percent   float64 `json:"percent"`
}

// EventStats represents event bus statistics
type EventStats struct {
	EventsReceived int64 `json:"events_received"`
	EventsSent     int64 `json:"events_sent"`
	EventsDropped  int64 `json:"events_dropped"`
}

// ClientConfig represents Salt API client configuration
type ClientConfig struct {
	BaseURL          string        `json:"base_url"`
	Username         string        `json:"username"`
	Password         string        `json:"password"`
	Eauth            string        `json:"eauth"`
	Timeout          time.Duration `json:"timeout"`
	MaxRetries       int           `json:"max_retries"`
	RetryDelay       time.Duration `json:"retry_delay"`
	TLSSkipVerify    bool          `json:"tls_skip_verify"`
	CACert           string        `json:"ca_cert,omitempty"`
	ClientCert       string        `json:"client_cert,omitempty"`
	ClientKey        string        `json:"client_key,omitempty"`
	TokenRefreshTime time.Duration `json:"token_refresh_time"`
}

// HTTPSaltClient implements SaltClient interface
type HTTPSaltClient struct {
	config        *ClientConfig
	token         string
	tokenExpiry   time.Time
	rc            *eos_io.RuntimeContext
}

// Error types for Salt client operations
type SaltError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Type    string `json:"type"`
}

func (e *SaltError) Error() string {
	return e.Message
}

// Common Salt error types
const (
	ErrAuthenticationFailed = "authentication_failed"
	ErrConnectionFailed     = "connection_failed"
	ErrCommandFailed        = "command_failed"
	ErrMinionNotFound       = "minion_not_found"
	ErrJobNotFound          = "job_not_found"
	ErrStateError           = "state_error"
	ErrOrchestrationError   = "orchestration_error"
	ErrTimeout              = "timeout"
	ErrInvalidRequest       = "invalid_request"
	ErrPermissionDenied     = "permission_denied"
)

// Salt client types
const (
	ClientTypeLocal      = "local"
	ClientTypeLocalAsync = "local_async"
	ClientTypeRunner     = "runner"
	ClientTypeWheel      = "wheel"
)

// Target types for Salt commands
const (
	TargetTypeGlob       = "glob"
	TargetTypePCRE       = "pcre"
	TargetTypeList       = "list"
	TargetTypeGrain      = "grain"
	TargetTypePillar     = "pillar"
	TargetTypeNodegroup  = "nodegroup"
	TargetTypeRange      = "range"
	TargetTypeCompound   = "compound"
	TargetTypeIPCIDR     = "ipcidr"
)

// Common Salt functions
const (
	FunctionTest       = "test.ping"
	FunctionCmd        = "cmd.run"
	FunctionState      = "state.apply"
	FunctionHighstate  = "state.highstate"
	FunctionPillar     = "pillar.items"
	FunctionGrains     = "grains.items"
	FunctionPkg        = "pkg.install"
	FunctionService    = "service.start"
	FunctionFile       = "file.managed"
)