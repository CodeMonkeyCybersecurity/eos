// Package events provides Wazuh MSSP event tracking functionality.
package events

import "time"

// EventListItem represents a single event in the MSSP platform.
type EventListItem struct {
	EventID     string                 `json:"event_id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        string                 `json:"type"`
	CustomerID  string                 `json:"customer_id"`
	CompanyName string                 `json:"company_name"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details"`
}

// EventList represents a list of events.
type EventList struct {
	Events    []EventListItem `json:"events"`
	Total     int             `json:"total"`
	Timestamp time.Time       `json:"timestamp"`
}
