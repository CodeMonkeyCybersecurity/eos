// pkg/alerts/model.go
package alerts

import (
	"html/template"
	"time"
)

type Alert struct {
	Time        time.Time
	Severity    int
	RuleID      string
	Title       string
	Description string        // human-readable summary
	HTMLDetails template.HTML // optional rich block if you already have markup
	Host        string
	Meta        map[string]any
}
