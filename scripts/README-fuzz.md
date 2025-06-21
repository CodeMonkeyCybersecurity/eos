# Fuzz Testing for Eos

This directory contains scripts and configuration for running fuzz tests on the Eos codebase.

## Quick Start

Run all fuzz tests with default 10-second duration:
```bash
./scripts/run-fuzz-tests.sh
```

Run with custom duration (e.g., 30 seconds):
```bash
./scripts/run-fuzz-tests.sh 30s
```

## Fuzz Test Coverage

The following packages have fuzz tests:

### pkg/crypto
- `FuzzValidateStrongPassword` - Tests password validation with various inputs
- `FuzzHashString` - Tests string hashing function
- `FuzzHashStrings` - Tests multiple string hashing
- `FuzzAllUnique` - Tests uniqueness validation
- `FuzzAllHashesPresent` - Tests hash presence validation
- `FuzzRedact` - Tests sensitive data redaction
- `FuzzInjectSecretsFromPlaceholders` - Tests secret injection logic
- `FuzzSecureZero` - Tests secure memory zeroing

### pkg/interaction
- `FuzzNormalizeYesNoInput` - Tests yes/no input normalization
- `FuzzValidateNonEmpty` - Tests non-empty validation
- `FuzzValidateUsername` - Tests username validation
- `FuzzValidateEmail` - Tests email validation
- `FuzzValidateURL` - Tests URL validation
- `FuzzValidateIP` - Tests IP address validation
- `FuzzValidateNoShellMeta` - Tests shell injection prevention

### pkg/parse
- `FuzzSplitAndTrim` - Tests CSV parsing and trimming logic

## GitHub Actions

Fuzz tests run automatically in CI/CD via `.github/workflows/fuzz.yml` on:
- Push to main branch
- Pull requests to main branch

Each fuzz test runs for 5 seconds in CI to balance coverage with build time.

## Running Individual Tests

Run a specific fuzz test:
```bash
go test -run=^FuzzValidateStrongPassword$ -fuzz=^FuzzValidateStrongPassword$ -fuzztime=10s ./pkg/crypto
```

## Adding New Fuzz Tests

1. Create a fuzz function in your `*_test.go` file:
```go
func FuzzMyFunction(f *testing.F) {
    f.Add("test input")
    f.Fuzz(func(t *testing.T, input string) {
        MyFunction(input)
    })
}
```

2. Add the test to `scripts/run-fuzz-tests.sh`
3. Add the test to `.github/workflows/fuzz.yml`

## Troubleshooting

**Error: "cannot use -fuzz flag with multiple packages"**
- Don't use `./...` with `-fuzz` flag
- Run fuzz tests for each package individually

**Error: "will not fuzz, -fuzz matches more than one fuzz test"** 
- Use exact regex patterns: `-fuzz=^FuzzFunctionName$`
- Don't use partial matches that could match multiple functions