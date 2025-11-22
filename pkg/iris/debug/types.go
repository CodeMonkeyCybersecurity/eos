// pkg/iris/debug/types.go
package debug

// IrisConfig represents the Iris configuration structure loaded from config.yaml
type IrisConfig struct {
	Temporal struct {
		HostPort  string `yaml:"host_port"`
		Namespace string `yaml:"namespace"`
		TaskQueue string `yaml:"task_queue"`
	} `yaml:"temporal"`
	AzureOpenAI struct {
		Endpoint       string `yaml:"endpoint"`
		APIKey         string `yaml:"api_key"`
		DeploymentName string `yaml:"deployment_name"`
		APIVersion     string `yaml:"api_version"`
	} `yaml:"azure_openai"`
	Email struct {
		SMTPHost string `yaml:"smtp_host"`
		SMTPPort int    `yaml:"smtp_port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		From     string `yaml:"from"`
		To       string `yaml:"to"`
	} `yaml:"email"`
	Webhook struct {
		Port int `yaml:"port"`
	} `yaml:"webhook"`
}

// CheckResult represents the result of a single diagnostic check
type CheckResult struct {
	Name        string
	Category    string
	Passed      bool
	Error       error
	Remediation []string
	Details     string
}

// DiagnosticConfig holds configuration for the diagnostic run
type DiagnosticConfig struct {
	ProjectDir string
	TestAlert  bool
	Verbose    bool
}
