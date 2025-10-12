#!/bin/bash
# Script to fix remaining complex logging violations

set -e

echo " Fixing remaining logging violations..."

# Function to add logger initialization if missing
add_logger_init() {
    local file=$1
    # Check if logger is already initialized
    if ! grep -q "logger := otelzap.Ctx(rc.Ctx)" "$file"; then
        # Find the start of the function and add logger initialization
        sed -i '' '/RunE:.*func.*{/,/^[[:space:]]*logger.*:=/{ 
            /RunE:.*func.*{/!b
            n
            /^[[:space:]]*logger.*:=/b
            i\
\		logger := otelzap.Ctx(rc.Ctx)
        }' "$file"
    fi
}

# Fix cmd/read/wazuh_ccs.go
echo " Fixing cmd/read/wazuh_ccs.go..."
file="./cmd/read/wazuh_ccs.go"
add_logger_init "$file"

# Replace complex formatted output with logger
sed -i '' 's/fmt\.Printf("Total: %d (Active: %d, Suspended: %d)\\n",/logger.Info("terminal prompt: Total", zap.Int("total",/' "$file"
sed -i '' 's/, zap\.Int("total",/, zap.Int("active",/' "$file"
sed -i '' 's/, zap\.Int("active",/, zap.Int("suspended",/' "$file"

# Replace table headers
sed -i '' 's/fmt\.Printf("%-20s %-10s %-10s %-30s %s\\n",/logger.Info("terminal prompt: Compliance details",/' "$file"
sed -i '' 's/"ID", "Status", "Score", "Description", "Last Check")/zap.String("headers", "ID Status Score Description Last Check"))/' "$file"

# Replace CPU/Memory/Disk output
sed -i '' 's/fmt\.Printf("CPU: %.1f \/ %.1f %s (%.1f%%)\\n",/logger.Info("terminal prompt: CPU usage", zap.Float64("used",/' "$file"
sed -i '' 's/fmt\.Printf("Memory: %.0f \/ %.0f %s (%.1f%%)\\n",/logger.Info("terminal prompt: Memory usage", zap.Float64("used",/' "$file"
sed -i '' 's/fmt\.Printf("Disk: %.0f \/ %.0f %s (%.1f%%)\\n",/logger.Info("terminal prompt: Disk usage", zap.Float64("used",/' "$file"

# Fix cmd/list/wazuh_ccs.go
echo " Fixing cmd/list/wazuh_ccs.go..."
file="./cmd/list/wazuh_ccs.go"
add_logger_init "$file"

# Replace table output
sed -i '' 's/fmt\.Printf("%-\*s %-\*s %-\*s %-\*s %-\*s %-\*s\\n",/logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s %-*s",/' "$file"
sed -i '' 's/fmt\.Printf("%-\*s %-\*s %-\*s %-\*s %-\*s\\n",/logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s",/' "$file"

# Fix cmd/self/ai/ai.go remaining issues
echo " Fixing cmd/self/ai/ai.go..."
file="./cmd/self/ai/ai.go"
# Replace complex Printf with logger
sed -i '' 's/fmt\.Printf(" Environment analysis completed: %d files, %d containers, %d services\\n",/logger.Info("terminal prompt: Environment analysis completed", zap.Int("files",/' "$file"
sed -i '' 's/, zap\.Int("files",/, zap.Int("containers",/' "$file"
sed -i '' 's/, zap\.Int("containers",/, zap.Int("services",/' "$file"

# Fix cmd/backup/list.go
echo " Fixing cmd/backup/list.go..."
file="./cmd/backup/list.go"
add_logger_init "$file"

# Replace table formatting
sed -i '' 's/fmt\.Printf("%-20s %-15s %-10s %-30s\\n",/logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-20s %-15s %-10s %-30s",/' "$file"
sed -i '' 's/fmt\.Printf("\\n%d backup(s) found\\n",/logger.Info("terminal prompt: Backups found", zap.Int("count",/' "$file"

echo "🎉 Manual fixes complete!"