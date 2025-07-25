#!/bin/bash
# Script to find all Salt CLI usage that needs to be migrated to API

echo "=== Finding Salt CLI Usage for Migration ==="
echo ""

echo "Files using salt-call:"
echo "====================="
grep -r "salt-call" --include="*.go" /opt/eos/ | grep -v "/vendor/" | grep -v "/examples/" | grep -v "_test.go" | cut -d: -f1 | sort | uniq

echo ""
echo "Files using salt-run:"
echo "===================="
grep -r "salt-run" --include="*.go" /opt/eos/ | grep -v "/vendor/" | grep -v "/examples/" | grep -v "_test.go" | cut -d: -f1 | sort | uniq

echo ""
echo "Files using salt-key:"
echo "===================="
grep -r "salt-key" --include="*.go" /opt/eos/ | grep -v "/vendor/" | grep -v "/examples/" | grep -v "_test.go" | cut -d: -f1 | sort | uniq

echo ""
echo "Files using 'salt ' command (excluding salt-call, salt-run, salt-key):"
echo "====================================================================="
grep -r "\"salt \"" --include="*.go" /opt/eos/ | grep -v "salt-call" | grep -v "salt-run" | grep -v "salt-key" | grep -v "/vendor/" | grep -v "/examples/" | grep -v "_test.go" | cut -d: -f1 | sort | uniq

echo ""
echo "Summary:"
echo "========"
echo "Total files needing migration:"
(grep -r "salt-call\|salt-run\|salt-key\|\"salt \"" --include="*.go" /opt/eos/ | grep -v "/vendor/" | grep -v "/examples/" | grep -v "_test.go" | cut -d: -f1 | sort | uniq | wc -l)