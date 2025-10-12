// pkg/metis/templates.go
//
// Embedded source code templates for Metis components
// These are written out during 'eos create metis'

package metis

// GetWorkerSource returns the complete worker/main.go source code
func GetWorkerSource() string {
	return `package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/ai/azopenai"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	"gopkg.in/gomail.v2"
	"gopkg.in/yaml.v3"
)

// ============================================================================
// Configuration
// ============================================================================

type Config struct {
	Temporal struct {
		HostPort  string ` + "`yaml:\"host_port\"`" + `
		Namespace string ` + "`yaml:\"namespace\"`" + `
		TaskQueue string ` + "`yaml:\"task_queue\"`" + `
	} ` + "`yaml:\"temporal\"`" + `
	AzureOpenAI struct {
		Endpoint       string ` + "`yaml:\"endpoint\"`" + `
		APIKey         string ` + "`yaml:\"api_key\"`" + `
		DeploymentName string ` + "`yaml:\"deployment_name\"`" + `
		APIVersion     string ` + "`yaml:\"api_version\"`" + `
	} ` + "`yaml:\"azure_openai\"`" + `
	Email struct {
		SMTPHost string ` + "`yaml:\"smtp_host\"`" + `
		SMTPPort int    ` + "`yaml:\"smtp_port\"`" + `
		Username string ` + "`yaml:\"username\"`" + `
		Password string ` + "`yaml:\"password\"`" + `
		From     string ` + "`yaml:\"from\"`" + `
		To       string ` + "`yaml:\"to\"`" + `
	} ` + "`yaml:\"email\"`" + `
}

var config Config

// ============================================================================
// Wazuh Alert Types
// ============================================================================

type WazuhAlert struct {
	Agent struct {
		Name string ` + "`json:\"name\"`" + `
		ID   string ` + "`json:\"id\"`" + `
	} ` + "`json:\"agent\"`" + `
	Data struct {
		Vulnerability struct {
			Severity string ` + "`json:\"severity\"`" + `
			Package  struct {
				Name string ` + "`json:\"name\"`" + `
			} ` + "`json:\"package\"`" + `
			Title string ` + "`json:\"title\"`" + `
		} ` + "`json:\"vulnerability\"`" + `
	} ` + "`json:\"data\"`" + `
}

// ============================================================================
// WORKFLOW
// ============================================================================

func ProcessWazuhAlertWorkflow(ctx workflow.Context, alert WazuhAlert) error {
	logger := workflow.GetLogger(ctx)
	logger.Info("Starting workflow for alert", "agent", alert.Agent.Name)

	ao := workflow.ActivityOptions{
		StartToCloseTimeout: 2 * time.Minute,
		RetryPolicy: &workflow.RetryPolicy{
			MaximumAttempts: 3,
		},
	}
	ctx = workflow.WithActivityOptions(ctx, ao)

	// Activity 1: Call Azure OpenAI
	var llmResponse string
	err := workflow.ExecuteActivity(ctx, CallAzureOpenAI, alert).Get(ctx, &llmResponse)
	if err != nil {
		logger.Error("Azure OpenAI call failed", "error", err)
		return fmt.Errorf("LLM analysis failed: %w", err)
	}
	logger.Info("LLM analysis complete", "response_length", len(llmResponse))

	// Activity 2: Send email
	err = workflow.ExecuteActivity(ctx, SendEmail, alert, llmResponse).Get(ctx, nil)
	if err != nil {
		logger.Error("Email sending failed", "error", err)
		return fmt.Errorf("email failed: %w", err)
	}

	logger.Info("Workflow completed successfully")
	return nil
}

// ============================================================================
// ACTIVITY 1: Call Azure OpenAI
// ============================================================================

func CallAzureOpenAI(ctx context.Context, alert WazuhAlert) (string, error) {
	log.Printf("[Activity] Calling Azure OpenAI for alert: %s", alert.Data.Vulnerability.Title)

	keyCredential := azcore.NewKeyCredential(config.AzureOpenAI.APIKey)
	client, err := azopenai.NewClientWithKeyCredential(
		config.AzureOpenAI.Endpoint,
		keyCredential,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create Azure OpenAI client: %w", err)
	}

	alertJSON, _ := json.MarshalIndent(alert, "", "  ")
	prompt := fmt.Sprintf(` + "`" + `You are a cybersecurity assistant helping a small business understand security alerts.

Here's a security alert that was detected:

%s

Please explain in simple terms:
1. What happened (in plain English)
2. How serious is this
3. What they should do about it
4. How to check if they're affected

Keep it clear, practical, and not too technical.` + "`" + `, string(alertJSON))

	messages := []azopenai.ChatRequestMessageClassification{
		&azopenai.ChatRequestSystemMessage{
			Content: azopenai.NewChatRequestSystemMessageContent("You are a helpful cybersecurity assistant."),
		},
		&azopenai.ChatRequestUserMessage{
			Content: azopenai.NewChatRequestUserMessageContent(prompt),
		},
	}

	resp, err := client.GetChatCompletions(ctx, azopenai.ChatCompletionsOptions{
		Messages:       messages,
		DeploymentName: &config.AzureOpenAI.DeploymentName,
		MaxTokens:      ptr(int32(1500)),
		Temperature:    ptr(float32(0.3)),
	}, nil)

	if err != nil {
		return "", fmt.Errorf("OpenAI API call failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("no response from OpenAI")
	}

	response := *resp.Choices[0].Message.Content
	log.Printf("[Activity] Received LLM response (%d chars)", len(response))
	return response, nil
}

// ============================================================================
// ACTIVITY 2: Send Email
// ============================================================================

func SendEmail(ctx context.Context, alert WazuhAlert, llmResponse string) error {
	log.Printf("[Activity] Sending email for alert: %s", alert.Data.Vulnerability.Title)

	subject := fmt.Sprintf("[SECURITY ALERT] %s on %s",
		alert.Data.Vulnerability.Severity,
		alert.Agent.Name,
	)

	body := fmt.Sprintf(` + "`" + `Security Alert from Delphi Notify

Alert: %s
Agent: %s (ID: %s)
Severity: %s

=== AI Analysis ===

%s

---
This alert was processed automatically by Delphi Notify
Powered by Code Monkey Cybersecurity
` + "`" + `, alert.Data.Vulnerability.Title,
		alert.Agent.Name,
		alert.Agent.ID,
		alert.Data.Vulnerability.Severity,
		llmResponse,
	)

	m := gomail.NewMessage()
	m.SetHeader("From", config.Email.From)
	m.SetHeader("To", config.Email.To)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)

	d := gomail.NewDialer(
		config.Email.SMTPHost,
		config.Email.SMTPPort,
		config.Email.Username,
		config.Email.Password,
	)

	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Printf("[Activity] Email sent successfully")
	return nil
}

// ============================================================================
// Main
// ============================================================================

func main() {
	configData, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatalf("Failed to read config.yaml: %v", err)
	}
	if err := yaml.Unmarshal(configData, &config); err != nil {
		log.Fatalf("Failed to parse config.yaml: %v", err)
	}

	log.Printf("Configuration loaded successfully")
	log.Printf("Temporal: %s", config.Temporal.HostPort)
	log.Printf("Task Queue: %s", config.Temporal.TaskQueue)

	c, err := client.Dial(client.Options{
		HostPort:  config.Temporal.HostPort,
		Namespace: config.Temporal.Namespace,
	})
	if err != nil {
		log.Fatalf("Unable to create Temporal client: %v", err)
	}
	defer func() { _ = c.Close() }()

	w := worker.New(c, config.Temporal.TaskQueue, worker.Options{})

	w.RegisterWorkflow(ProcessWazuhAlertWorkflow)
	w.RegisterActivity(CallAzureOpenAI)
	w.RegisterActivity(SendEmail)

	log.Printf("Starting Temporal worker...")
	log.Printf("Listening on task queue: %s", config.Temporal.TaskQueue)
	log.Printf("Worker is ready to process alerts!")

	err = w.Run(worker.InterruptCh())
	if err != nil {
		log.Fatalf("Unable to start worker: %v", err)
	}
}

func ptr[T any](v T) *T {
	return &v
}
`
}

// GetWebhookSource returns the complete webhook/main.go source code
func GetWebhookSource() string {
	return `package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"go.temporal.io/sdk/client"
	"gopkg.in/yaml.v3"
)

// ============================================================================
// Configuration
// ============================================================================

type Config struct {
	Temporal struct {
		HostPort  string ` + "`yaml:\"host_port\"`" + `
		Namespace string ` + "`yaml:\"namespace\"`" + `
		TaskQueue string ` + "`yaml:\"task_queue\"`" + `
	} ` + "`yaml:\"temporal\"`" + `
	Webhook struct {
		Port int ` + "`yaml:\"port\"`" + `
	} ` + "`yaml:\"webhook\"`" + `
}

var config Config
var temporalClient client.Client

// ============================================================================
// Wazuh Alert Types
// ============================================================================

type WazuhAlert struct {
	Agent struct {
		Name string ` + "`json:\"name\"`" + `
		ID   string ` + "`json:\"id\"`" + `
	} ` + "`json:\"agent\"`" + `
	Data struct {
		Vulnerability struct {
			Severity string ` + "`json:\"severity\"`" + `
			Package  struct {
				Name string ` + "`json:\"name\"`" + `
			} ` + "`json:\"package\"`" + `
			Title string ` + "`json:\"title\"`" + `
		} ` + "`json:\"vulnerability\"`" + `
	} ` + "`json:\"data\"`" + `
}

// ============================================================================
// HTTP Handlers
// ============================================================================

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("Received webhook from %s", r.RemoteAddr)

	var alert WazuhAlert
	if err := json.NewDecoder(r.Body).Decode(&alert); err != nil {
		log.Printf("Failed to parse alert: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	log.Printf("Alert received: %s on agent %s",
		alert.Data.Vulnerability.Title,
		alert.Agent.Name,
	)

	workflowOptions := client.StartWorkflowOptions{
		ID:        fmt.Sprintf("wazuh-alert-%s-%d", alert.Agent.ID, time.Now().Unix()),
		TaskQueue: config.Temporal.TaskQueue,
	}

	we, err := temporalClient.ExecuteWorkflow(
		context.Background(),
		workflowOptions,
		"ProcessWazuhAlertWorkflow",
		alert,
	)
	if err != nil {
		log.Printf("Failed to start workflow: %v", err)
		http.Error(w, "Failed to start workflow", http.StatusInternalServerError)
		return
	}

	log.Printf("Started workflow: %s (Run ID: %s)", we.GetID(), we.GetRunID())
	log.Printf("View in Temporal UI: http://localhost:8233/namespaces/default/workflows/%s", we.GetID())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":      "accepted",
		"workflow_id": we.GetID(),
		"run_id":      we.GetRunID(),
		"message":     "Alert processing started",
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "delphi-webhook",
	})
}

// ============================================================================
// Main
// ============================================================================

func main() {
	configData, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatalf("Failed to read config.yaml: %v", err)
	}
	if err := yaml.Unmarshal(configData, &config); err != nil {
		log.Fatalf("Failed to parse config.yaml: %v", err)
	}

	log.Printf("Configuration loaded successfully")

	temporalClient, err = client.Dial(client.Options{
		HostPort:  config.Temporal.HostPort,
		Namespace: config.Temporal.Namespace,
	})
	if err != nil {
		log.Fatalf("Unable to create Temporal client: %v", err)
	}
	defer func() { _ = temporalClient.Close() }()

	log.Printf("Connected to Temporal at %s", config.Temporal.HostPort)

	http.HandleFunc("/webhook", handleWebhook)
	http.HandleFunc("/health", handleHealth)

	addr := fmt.Sprintf(":%d", config.Webhook.Port)
	log.Printf("Starting webhook server on %s", addr)
	log.Printf("Ready to receive Wazuh alerts at http://localhost%s/webhook", addr)
	log.Printf("Health check available at http://localhost%s/health", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
`
}

// GetReadmeContent returns the README.md content
func GetReadmeContent() string {
	return `# Metis/Delphi - Security Alert Processing

Automated processing of Wazuh security alerts using Azure OpenAI and Temporal workflows.

## Architecture

` + "```" + `
Wazuh → HTTP Webhook → Temporal → [Azure OpenAI → Email] → Mailcow
                                    ↓
                                  Postgres (audit)
` + "```" + `

## Quick Start

### 1. Edit Configuration

` + "```bash" + `
nano config.yaml
` + "```" + `

Update these fields:
- ` + "`azure_openai.endpoint`" + ` - Your Azure OpenAI endpoint
- ` + "`azure_openai.api_key`" + ` - Your API key
- ` + "`azure_openai.deployment_name`" + ` - Your deployment name
- ` + "`email.smtp_host`" + ` - Your SMTP server
- ` + "`email.username`" + ` - SMTP username
- ` + "`email.password`" + ` - SMTP password
- ` + "`email.to`" + ` - Where to send alerts

### 2. Start Temporal

` + "```bash" + `
temporal server start-dev
` + "```" + `

### 3. Start Services

**Development (manual):**

` + "```bash" + `
# Terminal 1
go run worker/main.go

# Terminal 2
go run webhook/main.go
` + "```" + `

**Production (systemd):**

` + "```bash" + `
sudo cp metis-*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable metis-worker metis-webhook
sudo systemctl start metis-worker metis-webhook
` + "```" + `

### 4. Test

` + "```bash" + `
./scripts/test-alert.sh

# Or
eos debug metis --test
` + "```" + `

## Monitoring

- **Temporal UI:** http://localhost:8233
- **Worker logs:** ` + "`journalctl -u metis-worker -f`" + `
- **Webhook logs:** ` + "`journalctl -u metis-webhook -f`" + `
- **Debug tool:** ` + "`eos debug metis`" + `

## Troubleshooting

### Quick Diagnostic

` + "```bash" + `
eos debug metis
` + "```" + `

This checks:
- Project structure
- Configuration validity
- Temporal server connectivity
- Worker process status
- Webhook server status
- Azure OpenAI configuration
- SMTP configuration
- Recent workflows
- Go dependencies

### Common Issues

**Temporal not connected:**
` + "```bash" + `
temporal server start-dev
` + "```" + `

**Worker not processing:**
` + "```bash" + `
sudo systemctl restart metis-worker
# Or
go run worker/main.go
` + "```" + `

**Configuration issues:**
` + "```bash" + `
nano config.yaml
eos debug metis --verbose
` + "```" + `

**Dependencies issues:**
` + "```bash" + `
go mod tidy
` + "```" + `

## Architecture Details

### Components

1. **Webhook Server** (webhook/main.go)
   - Receives Wazuh alerts via HTTP POST
   - Starts Temporal workflows
   - Returns immediately (async processing)

2. **Temporal Worker** (worker/main.go)
   - Executes workflows and activities
   - Calls Azure OpenAI
   - Sends emails
   - Handles retries and failures

3. **Temporal Server**
   - Orchestrates workflows
   - Persists workflow state
   - Provides web UI

### Workflow

` + "```" + `
1. Wazuh sends alert → HTTP webhook
2. Webhook starts Temporal workflow
3. Workflow Activity 1: Call Azure OpenAI
4. Workflow Activity 2: Send email
5. Done - check email inbox
` + "```" + `

### Why Temporal?

- **Reliability:** Survives crashes, resumes from last successful step
- **Observability:** Web UI shows all workflows, their status, timeline
- **Retry Logic:** Automatic retries with exponential backoff
- **Scalability:** Run multiple workers to process more alerts

## Next Steps

1. **Add NATS integration** for better async processing
2. **Add HTML email formatting** for prettier alerts
3. **Add Postgres audit logging** to track all alerts
4. **Add more activities** (Slack notifications, ticket creation)

## Support

Created by Code Monkey Cybersecurity
ABN: 77 177 673 061
Motto: "Cybersecurity. With humans."

For issues:
- Run: ` + "`eos debug metis --verbose`" + `
- Check: http://localhost:8233
- Logs: ` + "`journalctl -u metis-worker -f`" + `
`
}
