#!/bin/bash

# Script to remove emojis from all files except test files
# Usage: ./remove-emojis.sh [--dry-run]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if dry-run mode
DRY_RUN=false
if [[ "$1" == "--dry-run" ]]; then
    DRY_RUN=true
    echo -e "${YELLOW}Running in DRY-RUN mode - no files will be modified${NC}\n"
fi

# Comprehensive emoji regex pattern covering major Unicode blocks
# This includes:
# - Emoticons (1F600-1F64F)
# - Miscellaneous Symbols and Pictographs (1F300-1F5FF)
# - Transport and Map Symbols (1F680-1F6FF)
# - Supplemental Symbols and Pictographs (1F900-1F9FF)
# - Symbols and Pictographs Extended-A (1FA70-1FAFF)
# - Enclosed Alphanumeric Supplement (flags, 1F1E6-1F1FF)
# - Dingbats (2700-27BF)
# - Miscellaneous Symbols (2600-26FF)
# - Variation Selectors (FE00-FE0F)
# - Zero Width Joiner sequences
EMOJI_PATTERN='[\x{1F600}-\x{1F64F}\x{1F300}-\x{1F5FF}\x{1F680}-\x{1F6FF}\x{1F1E0}-\x{1F1FF}\x{2600}-\x{26FF}\x{2700}-\x{27BF}\x{1F900}-\x{1F9FF}\x{1FA70}-\x{1FAFF}\x{1F018}-\x{1F270}\x{238C}-\x{2454}\x{20D0}-\x{20FF}\x{FE00}-\x{FE0F}\x{E0020}-\x{E007F}\x{200D}]'

# Pattern to identify test files
# Modify these patterns based on your project structure
TEST_FILE_PATTERNS=(
    "test/"
    "tests/"
    "__tests__/"
    "_test\."
    "\.test\."
    "\.spec\."
    "test_"
    "Test\."
    "Spec\."
)

# File extensions to process (text files only)
TEXT_EXTENSIONS=(
    "*.py"
    "*.js"
    "*.ts"
    "*.jsx"
    "*.tsx"
    "*.go"
    "*.rs"
    "*.java"
    "*.c"
    "*.cpp"
    "*.h"
    "*.hpp"
    "*.cs"
    "*.php"
    "*.rb"
    "*.swift"
    "*.kt"
    "*.scala"
    "*.sh"
    "*.bash"
    "*.zsh"
    "*.txt"
    "*.md"
    "*.markdown"
    "*.json"
    "*.yaml"
    "*.yml"
    "*.toml"
    "*.xml"
    "*.html"
    "*.css"
    "*.scss"
    "*.sass"
    "*.less"
    "*.sql"
    "*.r"
    "*.R"
)

# Function to check if a file is a test file
is_test_file() {
    local file="$1"
    for pattern in "${TEST_FILE_PATTERNS[@]}"; do
        if echo "$file" | grep -qE "$pattern"; then
            return 0  # true - is a test file
        fi
    done
    return 1  # false - not a test file
}

# Function to check if file has text extension
has_text_extension() {
    local file="$1"
    for ext in "${TEXT_EXTENSIONS[@]}"; do
        # Remove the * from the pattern for comparison
        ext_pattern="${ext#\*}"
        if [[ "$file" == *"$ext_pattern" ]]; then
            return 0  # true
        fi
    done
    return 1  # false
}

# Function to check if file contains emojis
contains_emojis() {
    local file="$1"
    # Use perl for better Unicode support
    if perl -ne "print if /$EMOJI_PATTERN/o" "$file" | grep -q .; then
        return 0  # true - contains emojis
    fi
    return 1  # false - no emojis
}

# Function to remove emojis from a file
remove_emojis_from_file() {
    local file="$1"
    
    # Create a temporary file
    local temp_file="${file}.emoji_tmp"
    
    # Remove emojis using perl (better Unicode support than sed)
    perl -pe "s/$EMOJI_PATTERN//g" "$file" > "$temp_file"
    
    if [[ $DRY_RUN == false ]]; then
        # Replace original file
        mv "$temp_file" "$file"
        echo -e "${GREEN}✓${NC} Removed emojis from: $file"
    else
        # Show what would be changed
        if ! cmp -s "$file" "$temp_file"; then
            echo -e "${BLUE}[DRY-RUN]${NC} Would remove emojis from: $file"
            # Show a diff sample
            echo -e "${YELLOW}  Sample changes:${NC}"
            diff -u "$file" "$temp_file" | head -20 | tail -15 || true
            echo ""
        fi
        rm "$temp_file"
    fi
}

# Main execution
echo -e "${BLUE}Starting emoji removal process...${NC}\n"

# Counter for stats
total_files=0
test_files_skipped=0
files_processed=0
files_with_emojis=0

# Get all tracked files from git
while IFS= read -r file; do
    # Skip if file doesn't exist (e.g., deleted files)
    [[ ! -f "$file" ]] && continue
    
    total_files=$((total_files + 1))
    
    # Check if it's a text file
    if ! has_text_extension "$file"; then
        continue
    fi
    
    # Check if it's a test file
    if is_test_file "$file"; then
        echo -e "${YELLOW}⊗${NC} Skipping test file: $file"
        test_files_skipped=$((test_files_skipped + 1))
        continue
    fi
    
    files_processed=$((files_processed + 1))
    
    # Check if file contains emojis
    if contains_emojis "$file"; then
        files_with_emojis=$((files_with_emojis + 1))
        remove_emojis_from_file "$file"
    fi
    
done < <(git ls-files)

# Summary
echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}Summary:${NC}"
echo -e "  Total files checked: $total_files"
echo -e "  Test files skipped: $test_files_skipped"
echo -e "  Non-test files processed: $files_processed"
echo -e "  Files with emojis found: $files_with_emojis"

if [[ $DRY_RUN == true ]]; then
    echo -e "\n${YELLOW}This was a DRY-RUN. Run without --dry-run to actually remove emojis.${NC}"
else
    echo -e "\n${GREEN}✓ Emoji removal complete!${NC}"
fi

echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

# Exit with success
exit 0