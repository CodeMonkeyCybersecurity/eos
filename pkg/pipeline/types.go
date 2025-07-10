// Package pipeline provides types and utilities for the Eos pipeline infrastructure.
// This includes webhook management, service workers, alerts, prompts, and A/B testing.
package pipeline


// WebhookStatus represents the status of a webhook configuration
type WebhookStatus struct {
	URL        string `json:"url"`
	Configured bool   `json:"configured"`
	Active     bool   `json:"active"`
	Error      string `json:"error,omitempty"`
}

// AlertStatus represents the status of alert configurations
type AlertStatus struct {
	Provider   string `json:"provider"`
	Configured bool   `json:"configured"`
	Active     bool   `json:"active"`
	Error      string `json:"error,omitempty"`
}

// PromptTemplate represents a prompt template configuration
type PromptTemplate struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Content     string   `json:"content"`
	Category    string   `json:"category"`
	Tags        []string `json:"tags,omitempty"`
}

// ABTestConfig represents the structure from prompt-ab-tester.py
type ABTestConfig struct {
	Experiments []ABTestExperiment `json:"experiments"`
}

type ABTestExperiment struct {
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	Status         string          `json:"status"` // active, paused, completed, draft
	StartDate      *string         `json:"start_date,omitempty"`
	EndDate        *string         `json:"end_date,omitempty"`
	Variants       []ABTestVariant `json:"variants"`
	CohortStrategy string          `json:"cohort_strategy"` // agent_rule, agent_only, rule_only
	StickySessions bool            `json:"sticky_sessions"`
	TargetRules    []int           `json:"target_rules"` // specific rule IDs, empty = all
	MinRuleLevel   int             `json:"min_rule_level"`
	SampleRate     float64         `json:"sample_rate"` // 0.0-1.0
}

type ABTestVariant struct {
	Name        string                 `json:"name"`
	PromptType  string                 `json:"prompt_type"` // maps to parser_type enum
	Weight      float64                `json:"weight"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}
