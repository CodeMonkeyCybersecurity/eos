#!/bin/bash
# Script to add t.Parallel() to test functions
# Adds t.Parallel() as first line after function signature and in t.Run() subtests
#
# Usage: ./scripts/add_parallel.sh <file1> <file2> ...

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ $# -eq 0 ]; then
    echo "Usage: $0 <test_file>..."
    echo "Example: $0 pkg/crypto/bcrypt_test.go"
    exit 1
fi

add_parallel_to_file() {
    local file=$1

    echo -e "${YELLOW}Processing:${NC} $file"

    # Create backup
    cp "$file" "${file}.bak"

    # Use awk to add t.Parallel() after test function declarations and in t.Run() blocks
    awk '
    /^func Test.*\(t \*testing\.T\) \{$/ {
        print $0
        # Check if next line already has t.Parallel()
        getline nextline
        if (nextline !~ /t\.Parallel\(\)/) {
            print "\tt.Parallel()"
            print nextline
        } else {
            print nextline
        }
        next
    }
    /t\.Run\(.*func\(t \*testing\.T\) \{$/ {
        print $0
        # Check if next line already has t.Parallel()
        getline nextline
        if (nextline !~ /t\.Parallel\(\)/) {
            # Match indentation of the t.Run line and add one more tab
            match($0, /^[ \t]*/)
            indent = substr($0, RSTART, RLENGTH) "\t\t"
            print indent "t.Parallel()"
            print nextline
        } else {
            print nextline
        }
        next
    }
    { print }
    ' "${file}.bak" > "$file"

    # Check if file was actually modified
    if ! diff -q "$file" "${file}.bak" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓ Added t.Parallel() calls${NC}"
        rm "${file}.bak"
    else
        echo "  - No changes needed (already parallelized)"
        mv "${file}.bak" "$file"
    fi
}

# Process each file
for file in "$@"; do
    if [ -f "$file" ]; then
        add_parallel_to_file "$file"
    else
        echo -e "${RED}✗ File not found:${NC} $file"
    fi
done

echo ""
echo -e "${GREEN}Done!${NC}"
echo "Next steps:"
echo "  1. Review changes: git diff"
echo "  2. Run tests: go test -v <packages>"
echo "  3. Commit: git add -A && git commit -m 'feat(tests): add t.Parallel() for concurrent test execution'"
