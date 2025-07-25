package remotedebug

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// KernelLogRetriever handles kernel log retrieval
type KernelLogRetriever struct {
	client   *SSHClient
	sudoPass string
}

// NewKernelLogRetriever creates a new kernel log retriever
func NewKernelLogRetriever(client *SSHClient, sudoPass string) *KernelLogRetriever {
	return &KernelLogRetriever{
		client:   client,
		sudoPass: sudoPass,
	}
}

// RetrieveKernelLogs attempts multiple strategies to get kernel logs
func (k *KernelLogRetriever) RetrieveKernelLogs(since time.Duration) (*KernelLogs, error) {
	logs := &KernelLogs{
		RetrievedAt: time.Now(),
		Messages:    []KernelMessage{},
	}
	
	// Try different retrieval methods
	
	// Method 1: Try dmesg first (most recent, might need privileges)
	dmesgLogs, err := k.retrieveDmesg()
	if err == nil && len(dmesgLogs) > 0 {
		logs.Messages = append(logs.Messages, dmesgLogs...)
		logs.Source = "dmesg"
	}
	
	// Method 2: Try journalctl (most comprehensive if systemd is used)
	journalLogs, err := k.retrieveJournalKernelLogs(since)
	if err == nil && len(journalLogs) > 0 {
		logs.Messages = mergeKernelMessages(logs.Messages, journalLogs)
		if logs.Source != "" {
			logs.Source += ",journalctl"
		} else {
			logs.Source = "journalctl"
		}
	}
	
	// Method 3: Traditional log files (fallback for older systems)
	fileLogs, err := k.retrieveTraditionalKernelLogs(since)
	if err == nil && len(fileLogs) > 0 {
		logs.Messages = mergeKernelMessages(logs.Messages, fileLogs)
		if logs.Source != "" {
			logs.Source += ",files"
		} else {
			logs.Source = "files"
		}
	}
	
	// Method 4: Emergency retrieval if we got nothing
	if len(logs.Messages) == 0 {
		emergencyLogs, _ := k.emergencyKernelLogRetrieval()
		logs.Messages = emergencyLogs
		logs.Source = "emergency"
	}
	
	return logs, nil
}

// retrieveDmesg gets kernel messages from dmesg command
func (k *KernelLogRetriever) retrieveDmesg() ([]KernelMessage, error) {
	// Check dmesg capabilities
	capsCmd := "dmesg --help 2>&1 | grep -E '(-T|--time)' | wc -l"
	capsOutput, _ := k.client.ExecuteCommand(capsCmd, false)
	hasTimeSupport := strings.TrimSpace(capsOutput) != "0"
	
	var dmesgCmd string
	if hasTimeSupport {
		// Modern dmesg with timestamp decoding
		dmesgCmd = "dmesg -T --level=err,warn,info,debug"
	} else {
		// Fallback for older systems
		dmesgCmd = "dmesg"
	}
	
	output, err := k.client.ExecuteCommand(dmesgCmd, true)
	if err != nil {
		// Try without sudo
		output, err = k.client.ExecuteCommand(dmesgCmd, false)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve dmesg: %w", err)
		}
	}
	
	return k.parseDmesgOutput(output, hasTimeSupport), nil
}

// parseDmesgOutput handles both timestamped and non-timestamped dmesg output
func (k *KernelLogRetriever) parseDmesgOutput(output string, hasTimestamps bool) []KernelMessage {
	var messages []KernelMessage
	lines := strings.Split(output, "\n")
	
	// Get boot time for relative timestamp calculation
	bootTime := k.getSystemBootTime()
	
	for _, line := range lines {
		if line == "" {
			continue
		}
		
		msg := KernelMessage{Raw: line}
		
		if hasTimestamps {
			// Parse modern dmesg format: [Timestamp] message
			if idx := strings.Index(line, "]"); idx > 0 && strings.HasPrefix(line, "[") {
				timeStr := strings.TrimPrefix(line[:idx], "[")
				msg.Message = strings.TrimSpace(line[idx+1:])
				
				// Try to parse various timestamp formats
				for _, format := range []string{
					"Mon Jan 2 15:04:05 2006",
					"2006-01-02 15:04:05",
				} {
					if t, err := time.Parse(format, timeStr); err == nil {
						msg.Timestamp = t
						break
					}
				}
			} else {
				msg.Message = line
			}
		} else {
			// Parse traditional format: [seconds.microseconds] message
			re := regexp.MustCompile(`^\[\s*(\d+\.\d+)\]\s*(.*)`)
			if match := re.FindStringSubmatch(line); len(match) == 3 {
				if seconds, err := strconv.ParseFloat(match[1], 64); err == nil {
					// Calculate absolute time from boot time
					msg.Timestamp = bootTime.Add(time.Duration(seconds * float64(time.Second)))
				}
				msg.Message = match[2]
			} else {
				msg.Message = line
			}
		}
		
		// Extract severity level
		msg.Level = k.extractLogLevel(msg.Message)
		
		// Categorize the message
		msg.Category = k.categorizeKernelMessage(msg.Message)
		
		messages = append(messages, msg)
	}
	
	return messages
}

// retrieveJournalKernelLogs uses systemd journal for kernel logs
func (k *KernelLogRetriever) retrieveJournalKernelLogs(since time.Duration) ([]KernelMessage, error) {
	sinceStr := fmt.Sprintf("%.0f seconds ago", since.Seconds())
	cmd := fmt.Sprintf(`journalctl -k --since="%s" --no-pager`, sinceStr)
	
	output, err := k.client.ExecuteCommand(cmd, true)
	if err != nil {
		return nil, err
	}
	
	return k.parseJournalOutput(output), nil
}

// parseJournalOutput parses journalctl output
func (k *KernelLogRetriever) parseJournalOutput(output string) []KernelMessage {
	var messages []KernelMessage
	
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "-- ") {
			continue
		}
		
		msg := KernelMessage{Raw: line}
		
		// Journal format: MMM DD HH:MM:SS hostname kernel: message
		parts := strings.SplitN(line, " kernel: ", 2)
		if len(parts) == 2 {
			msg.Message = parts[1]
			
			// Try to parse timestamp from the beginning
			timePart := strings.TrimSpace(parts[0])
			// Remove hostname
			if idx := strings.LastIndex(timePart, " "); idx > 0 {
				timePart = timePart[:idx]
			}
			
			// Parse time (journal uses current year)
			now := time.Now()
			timeStr := fmt.Sprintf("%d %s", now.Year(), timePart)
			if t, err := time.Parse("2006 Jan 2 15:04:05", timeStr); err == nil {
				msg.Timestamp = t
			}
		} else {
			msg.Message = line
		}
		
		msg.Level = k.extractLogLevel(msg.Message)
		msg.Category = k.categorizeKernelMessage(msg.Message)
		
		messages = append(messages, msg)
	}
	
	return messages
}

// retrieveTraditionalKernelLogs gets logs from traditional log files
func (k *KernelLogRetriever) retrieveTraditionalKernelLogs(since time.Duration) ([]KernelMessage, error) {
	// Find kernel log files
	findCmd := `find /var/log -name "kern.log*" -o -name "messages*" -o -name "syslog*" | grep -v ".gz" | head -5`
	filesOutput, err := k.client.ExecuteCommand(findCmd, true)
	if err != nil {
		return nil, err
	}
	
	var messages []KernelMessage
	files := strings.Split(filesOutput, "\n")
	
	for _, file := range files {
		if file == "" {
			continue
		}
		
		// Get recent entries from the file
		cmd := fmt.Sprintf(`tail -1000 %s | grep -i kernel`, file)
		output, err := k.client.ExecuteCommand(cmd, true)
		if err == nil {
			fileMessages := k.parseTraditionalLogOutput(output)
			messages = append(messages, fileMessages...)
		}
	}
	
	return messages, nil
}

// parseTraditionalLogOutput parses traditional syslog format
func (k *KernelLogRetriever) parseTraditionalLogOutput(output string) []KernelMessage {
	var messages []KernelMessage
	
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		
		msg := KernelMessage{
			Raw:     line,
			Message: line,
		}
		
		// Try to extract timestamp and message
		// Format: MMM DD HH:MM:SS hostname kernel: message
		if idx := strings.Index(line, " kernel: "); idx > 0 {
			msg.Message = line[idx+9:]
			
			// Parse timestamp
			timePart := line[:idx]
			if idx2 := strings.Index(timePart, " "); idx2 > 0 {
				timePart = timePart[idx2+1:]
			}
			
			// Traditional syslog doesn't include year
			now := time.Now()
			timeStr := fmt.Sprintf("%d %s", now.Year(), timePart)
			if t, err := time.Parse("2006 Jan 2 15:04:05", timeStr); err == nil {
				msg.Timestamp = t
			}
		}
		
		msg.Level = k.extractLogLevel(msg.Message)
		msg.Category = k.categorizeKernelMessage(msg.Message)
		
		messages = append(messages, msg)
	}
	
	return messages
}

// emergencyKernelLogRetrieval tries to get any kernel logs when standard methods fail
func (k *KernelLogRetriever) emergencyKernelLogRetrieval() ([]KernelMessage, error) {
	var messages []KernelMessage
	
	// Try to find any kernel panic or error messages
	strategies := []struct {
		name string
		cmd  string
	}{
		{
			"Recent kernel errors",
			`grep -r "kernel:" /var/log 2>/dev/null | grep -E "error|fail|panic|oops" | tail -50`,
		},
		{
			"Kernel panics",
			`find /var/log -type f -exec grep -l "kernel panic\|BUG:\|Oops:" {} \; 2>/dev/null | xargs grep -h "kernel panic\|BUG:\|Oops:" 2>/dev/null | tail -20`,
		},
		{
			"Last boot messages",
			`grep -i kernel /var/log/boot.log 2>/dev/null | tail -50`,
		},
	}
	
	for _, strategy := range strategies {
		output, err := k.client.ExecuteCommand(strategy.cmd, true)
		if err == nil && output != "" {
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if line != "" {
					messages = append(messages, KernelMessage{
						Raw:       line,
						Message:   line,
						Source:    strategy.name,
						Timestamp: time.Now(), // Best guess
						Level:     k.extractLogLevel(line),
						Category:  k.categorizeKernelMessage(line),
					})
				}
			}
		}
	}
	
	return messages, nil
}

// getSystemBootTime retrieves system boot time
func (k *KernelLogRetriever) getSystemBootTime() time.Time {
	// Try to get boot time from uptime -s
	cmd := "uptime -s 2>/dev/null"
	output, err := k.client.ExecuteCommand(cmd, false)
	if err == nil {
		bootTimeStr := strings.TrimSpace(output)
		if t, err := time.Parse("2006-01-02 15:04:05", bootTimeStr); err == nil {
			return t
		}
	}
	
	// Fallback: calculate from uptime
	uptimeCmd := "cat /proc/uptime"
	uptimeOutput, err := k.client.ExecuteCommand(uptimeCmd, false)
	if err == nil {
		fields := strings.Fields(uptimeOutput)
		if len(fields) > 0 {
			if seconds, err := strconv.ParseFloat(fields[0], 64); err == nil {
				return time.Now().Add(-time.Duration(seconds) * time.Second)
			}
		}
	}
	
	// Default to 1 hour ago
	return time.Now().Add(-time.Hour)
}

// extractLogLevel extracts the log level from a kernel message
func (k *KernelLogRetriever) extractLogLevel(message string) string {
	lowerMsg := strings.ToLower(message)
	
	if strings.Contains(lowerMsg, "panic") || strings.Contains(lowerMsg, "bug:") || strings.Contains(lowerMsg, "oops:") {
		return "panic"
	}
	if strings.Contains(lowerMsg, "error") || strings.Contains(lowerMsg, "fail") {
		return "error"
	}
	if strings.Contains(lowerMsg, "warn") {
		return "warning"
	}
	if strings.Contains(lowerMsg, "debug") {
		return "debug"
	}
	
	return "info"
}

// categorizeKernelMessage categorizes a kernel message
func (k *KernelLogRetriever) categorizeKernelMessage(message string) string {
	lowerMsg := strings.ToLower(message)
	
	categories := map[string][]string{
		"memory":  {"memory", "oom", "swap", "page", "allocation"},
		"disk":    {"ata", "sata", "scsi", "i/o error", "block", "filesystem", "ext4", "xfs"},
		"network": {"eth", "wlan", "net", "tcp", "udp", "nf_", "netfilter"},
		"cpu":     {"cpu", "processor", "mce", "nmi"},
		"usb":     {"usb", "hub"},
		"pci":     {"pci", "pcie"},
		"driver":  {"driver", "module", "firmware"},
		"power":   {"acpi", "power", "suspend", "resume", "battery"},
	}
	
	for category, keywords := range categories {
		for _, keyword := range keywords {
			if strings.Contains(lowerMsg, keyword) {
				return category
			}
		}
	}
	
	return "general"
}

// mergeKernelMessages merges and deduplicates kernel messages
func mergeKernelMessages(existing, new []KernelMessage) []KernelMessage {
	// Create a map to track unique messages
	messageMap := make(map[string]KernelMessage)
	
	// Add existing messages
	for _, msg := range existing {
		key := fmt.Sprintf("%d_%s", msg.Timestamp.Unix(), msg.Message)
		messageMap[key] = msg
	}
	
	// Add new messages
	for _, msg := range new {
		key := fmt.Sprintf("%d_%s", msg.Timestamp.Unix(), msg.Message)
		if _, exists := messageMap[key]; !exists {
			messageMap[key] = msg
		}
	}
	
	// Convert back to slice
	var result []KernelMessage
	for _, msg := range messageMap {
		result = append(result, msg)
	}
	
	return result
}