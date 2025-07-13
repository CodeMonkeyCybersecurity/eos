package domain

import (
	"time"
)

// Secret represents a domain secret with metadata
type Secret struct {
	Key       string            `json:"key"`
	Value     string            `json:"-"` // Never serialize the actual value
	Metadata  map[string]string `json:"metadata,omitempty"`
	Version   int               `json:"version,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
	Path      string            `json:"path"`
	Data      map[string]interface{} `json:"-"` // Don't serialize raw data
}