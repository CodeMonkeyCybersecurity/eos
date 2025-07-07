#!/bin/bash
# Legacy wrapper for run-fuzz-tests.sh - DEPRECATED
# This script is maintained for backward compatibility only

echo "⚠️  DEPRECATION NOTICE"
echo "==================="
echo "run-fuzz-tests.sh is deprecated and will be removed in a future version."
echo ""
echo "Please use the new EOS Fuzzing Framework:"
echo "  scripts/eos-fuzz.sh         # Main fuzzing framework"
echo "  scripts/eos-fuzz-ci.sh      # CI/CD optimized version"
echo ""
echo "The new framework provides:"
echo "  ✅ STACK.md architectural compliance"
echo "  ✅ Enhanced security and error handling" 
echo "  ✅ Better resource management"
echo "  ✅ CI/CD integration"
echo "  ✅ Comprehensive reporting"
echo ""
echo "Migrating your usage:"
echo "  OLD: ./scripts/run-fuzz-tests.sh 30s"
echo "  NEW: ./scripts/eos-fuzz.sh 30s"
echo ""
echo "  OLD: PARALLEL_JOBS=8 ./scripts/run-fuzz-tests.sh 5m"
echo "  NEW: PARALLEL_JOBS=8 ./scripts/eos-fuzz.sh 5m"
echo ""
echo "Proceeding with legacy script in 5 seconds..."
echo "Press Ctrl+C to cancel and migrate to new framework."

sleep 5

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Execute the original script
exec "$SCRIPT_DIR/run-fuzz-tests.sh" "$@"