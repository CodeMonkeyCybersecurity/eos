#!/bin/bash
# Run all fuzz tests for the Eos project
# Usage: ./scripts/run-fuzz-tests.sh [fuzztime]

set -e

FUZZTIME="${1:-10s}"

echo " Running fuzz tests with ${FUZZTIME} duration..."
echo " Working directory: $(pwd)"
echo ""

echo " Fuzzing crypto package..."
go test -run=^FuzzValidateStrongPassword$ -fuzz=^FuzzValidateStrongPassword$ -fuzztime="${FUZZTIME}" ./pkg/crypto
go test -run=^FuzzHashString$ -fuzz=^FuzzHashString$ -fuzztime="${FUZZTIME}" ./pkg/crypto
go test -run=^FuzzHashStrings$ -fuzz=^FuzzHashStrings$ -fuzztime="${FUZZTIME}" ./pkg/crypto
go test -run=^FuzzAllUnique$ -fuzz=^FuzzAllUnique$ -fuzztime="${FUZZTIME}" ./pkg/crypto
go test -run=^FuzzAllHashesPresent$ -fuzz=^FuzzAllHashesPresent$ -fuzztime="${FUZZTIME}" ./pkg/crypto
go test -run=^FuzzRedact$ -fuzz=^FuzzRedact$ -fuzztime="${FUZZTIME}" ./pkg/crypto
go test -run=^FuzzInjectSecretsFromPlaceholders$ -fuzz=^FuzzInjectSecretsFromPlaceholders$ -fuzztime="${FUZZTIME}" ./pkg/crypto
go test -run=^FuzzSecureZero$ -fuzz=^FuzzSecureZero$ -fuzztime="${FUZZTIME}" ./pkg/crypto

echo ""
echo " Fuzzing interaction package..."
go test -run=^FuzzNormalizeYesNoInput$ -fuzz=^FuzzNormalizeYesNoInput$ -fuzztime="${FUZZTIME}" ./pkg/interaction
go test -run=^FuzzValidateNonEmpty$ -fuzz=^FuzzValidateNonEmpty$ -fuzztime="${FUZZTIME}" ./pkg/interaction
go test -run=^FuzzValidateUsername$ -fuzz=^FuzzValidateUsername$ -fuzztime="${FUZZTIME}" ./pkg/interaction
go test -run=^FuzzValidateEmail$ -fuzz=^FuzzValidateEmail$ -fuzztime="${FUZZTIME}" ./pkg/interaction
go test -run=^FuzzValidateURL$ -fuzz=^FuzzValidateURL$ -fuzztime="${FUZZTIME}" ./pkg/interaction
go test -run=^FuzzValidateIP$ -fuzz=^FuzzValidateIP$ -fuzztime="${FUZZTIME}" ./pkg/interaction
go test -run=^FuzzValidateNoShellMeta$ -fuzz=^FuzzValidateNoShellMeta$ -fuzztime="${FUZZTIME}" ./pkg/interaction

echo ""
echo " Fuzzing parse package..."
go test -run=^FuzzSplitAndTrim$ -fuzz=^FuzzSplitAndTrim$ -fuzztime="${FUZZTIME}" ./pkg/parse

echo ""
echo " All fuzz tests completed successfully!"
echo " No issues found during fuzzing with ${FUZZTIME} duration."