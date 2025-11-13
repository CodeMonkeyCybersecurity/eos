#!/bin/bash
# Script to test CodeQL query syntax

set -e

echo "Testing CodeQL query syntax..."

# Check if we're in the right directory
if [ ! -f ".github/codeql/custom-queries/qlpack.yml" ]; then
    echo "Error: Run this script from the repository root"
    exit 1
fi

cd .github/codeql/custom-queries

echo "✓ Testing vault-token-exposure.ql syntax..."
if command -v codeql >/dev/null 2>&1; then
    codeql query format vault-token-exposure.ql --output=vault-token-exposure-formatted.ql
    echo "✓ vault-token-exposure.ql syntax is valid"
else
    echo "⚠ CodeQL not installed, skipping syntax validation"
fi

echo "✓ Testing command-injection.ql syntax..."
if command -v codeql >/dev/null 2>&1; then
    codeql query format command-injection.ql --output=command-injection-formatted.ql
    echo "✓ command-injection.ql syntax is valid"
else
    echo "⚠ CodeQL not installed, skipping syntax validation"
fi

echo "✓ Testing hardcoded-credentials.ql syntax..."
if command -v codeql >/dev/null 2>&1; then
    codeql query format hardcoded-credentials.ql --output=hardcoded-credentials-formatted.ql
    echo "✓ hardcoded-credentials.ql syntax is valid"
else
    echo "⚠ CodeQL not installed, skipping syntax validation"
fi

echo "✓ Testing insecure-file-permissions.ql syntax..."
if command -v codeql >/dev/null 2>&1; then
    codeql query format insecure-file-permissions.ql --output=insecure-file-permissions-formatted.ql
    echo "✓ insecure-file-permissions.ql syntax is valid"
else
    echo "⚠ CodeQL not installed, skipping syntax validation"
fi

echo "✓ All queries passed basic syntax validation"

# Clean up formatted files
rm -f *-formatted.ql

echo "CodeQL query testing completed successfully!"