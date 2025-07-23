package salt

// Command represents a Salt command to execute
type Command struct {
	Client   string            // local, local_async, runner, etc.
	Target   string            // targeting expression
	Function string            // function to run
	Args     []string          // positional arguments
	Kwargs   map[string]string // keyword arguments
}

// AuthResponse represents the login response
type AuthResponse struct {
	Return []struct {
		Token  string   `json:"token"`
		Expire float64  `json:"expire"`
		Start  float64  `json:"start"`
		User   string   `json:"user"`
		EAuth  string   `json:"eauth"`
		Perms  []string `json:"perms"`
	} `json:"return"`
}

// CommandResponse represents a command execution response
type CommandResponse struct {
	Return []map[string]interface{} `json:"return"`
}

// CommandResult wraps the raw result with helper methods
type CommandResult struct {
	Raw    map[string]interface{}
	client *Client
}

// StateResult represents the result of a state execution
type StateResult struct {
	States    map[string]StateExecutionResult
	Completed bool
	Failed    bool
	Errors    []string
}

// StateExecutionResult represents a single state execution result
type StateExecutionResult struct {
	ID       string
	Result   bool
	Comment  string
	Changes  map[string]interface{}
	Duration float64
}

// StateProgress represents progress during state execution
type StateProgress struct {
	State     string
	Completed bool
	Success   bool
	Message   string
}

// EventData represents a server-sent event
type EventData struct {
	Tag  string                 `json:"tag"`
	Data map[string]interface{} `json:"data"`
}

// JobReturn represents a job return event
type JobReturn struct {
	Return map[string]struct {
		Result   bool                   `json:"result"`
		Comment  string                 `json:"comment"`
		Changes  map[string]interface{} `json:"changes"`
		Duration float64                `json:"duration"`
	} `json:"return"`
}

// ConsulStatus represents the current Consul installation status
type ConsulStatus struct {
	Installed      bool
	Running        bool
	Failed         bool
	ConfigValid    bool
	Version        string
	ServiceStatus  string
	ClusterMembers int
	LastError      string
}