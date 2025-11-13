// pkg/iris/types.go

package iris

// IrisConfiguration holds configuration for Iris installation
type IrisConfiguration struct {
	Azure struct {
		Endpoint       string
		APIKey         string
		DeploymentName string
		APIVersion     string
	}
	Email struct {
		SMTPHost string
		SMTPPort int
		Username string
		Password string
		From     string
		To       string
	}
	Webhook struct {
		Port int
	}
	Temporal struct {
		HostPort  string
		Namespace string
		TaskQueue string
	}
}
