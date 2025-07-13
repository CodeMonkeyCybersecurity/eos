#!/bin/bash
# Script to fix logging violations in Eos codebase
# Replaces fmt.Printf/Println/Print with proper otelzap logging

set -e

echo "🔧 Fixing logging violations in Eos codebase..."

# Function to check if file imports required packages
has_logger() {
    local file=$1
    grep -q "otelzap.Ctx(rc.Ctx)" "$file" || grep -q "logger :=" "$file"
}

# Function to add logger initialization if missing
add_logger_init() {
    local file=$1
    # Check if logger is already initialized
    if ! has_logger "$file"; then
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

# Process each go file in cmd directory
find ./cmd -name "*.go" -type f | while read -r file; do
    # Skip test files
    if [[ "$file" == *_test.go ]]; then
        continue
    fi
    
    # Count violations in this file
    violations=$(grep -c "fmt\.Printf\|fmt\.Println\|fmt\.Print[^f^l]" "$file" || true)
    
    if [ "$violations" -gt 0 ]; then
        echo "📝 Processing $file ($violations violations)..."
        
        # Backup original file
        cp "$file" "$file.bak"
        
        # Add logger initialization if needed
        add_logger_init "$file"
        
        # Replace fmt.Printf with logger.Info for user-facing messages
        # Handle multi-line format strings
        perl -i -pe 's/fmt\.Printf\("\\n(.+?)\\n"\)/logger.Info("terminal prompt: $1")/g' "$file"
        perl -i -pe 's/fmt\.Printf\("(.+?)\\n"(.*?)\)/logger.Info("terminal prompt: $1"$2)/g' "$file"
        perl -i -pe 's/fmt\.Printf\("(.+?)"(.*?)\)/logger.Info("terminal prompt: $1"$2)/g' "$file"
        
        # Replace fmt.Println 
        perl -i -pe 's/fmt\.Println\("(.+?)"\)/logger.Info("terminal prompt: $1")/g' "$file"
        perl -i -pe 's/fmt\.Println\((.*?)\)/logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", $1)))/g' "$file"
        
        # Replace fmt.Print (without ln or f)
        perl -i -pe 's/fmt\.Print\("(.+?)"\)/logger.Info("terminal prompt: $1")/g' "$file"
        
        # Special handling for formatted strings with multiple arguments
        # fmt.Printf("Port: %d\n", port) -> logger.Info("terminal prompt: Port", zap.Int("port", port))
        perl -i -pe 's/fmt\.Printf\("(\w+):\s*%d\\n",\s*(\w+)\)/logger.Info("terminal prompt: $1", zap.Int("$2", $2))/g' "$file"
        perl -i -pe 's/fmt\.Printf\("(\w+):\s*%s\\n",\s*(\w+)\)/logger.Info("terminal prompt: $1", zap.String("$2", $2))/g' "$file"
        
        # Handle error cases
        perl -i -pe 's/fmt\.Printf\("(Error|Failed|Warning):\s*%v\\n",\s*(\w+)\)/logger.Error("$1", zap.Error($2))/g' "$file"
        
        # Ensure fmt import is not removed if still needed
        if grep -q "fmt\." "$file" && ! grep -q '"fmt"' "$file"; then
            # fmt is still used but import might be missing
            true
        elif ! grep -q "fmt\." "$file" && grep -q '"fmt"' "$file"; then
            # Remove unused fmt import
            sed -i '' '/"fmt"/d' "$file"
        fi
        
        # Verify no violations remain
        remaining=$(grep -c "fmt\.Printf\|fmt\.Println\|fmt\.Print[^f^l]" "$file" || true)
        if [ "$remaining" -eq 0 ]; then
            echo "✅ Fixed all violations in $file"
            rm "$file.bak"
        else
            echo "⚠️  $remaining violations remain in $file (manual fix needed)"
        fi
    fi
done

echo "🎉 Logging violation fixes complete!"
echo "⚠️  Please review changes and run tests before committing"