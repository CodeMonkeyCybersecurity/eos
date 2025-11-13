package events

import (
	"fmt"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// OutputEventTable formats and displays event list as a table.
func OutputEventTable(logger otelzap.LoggerWithCtx, list EventList) error {
	logger.Info("terminal prompt: Recent Events", zap.Int("total", list.Total))
	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 120)))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-20s %-20s %-15s %-20s %s",
		"Timestamp", "Type", "Customer ID", "Company", "Message")))
	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 120)))

	for _, event := range list.Events {
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-20s %-20s %-15s %-20s %s",
			event.Timestamp.Format("2006-01-02 15:04:05"),
			event.Type,
			event.CustomerID,
			truncate(event.CompanyName, 20),
			truncate(event.Message, 40))))
	}

	return nil
}

// truncate truncates a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
