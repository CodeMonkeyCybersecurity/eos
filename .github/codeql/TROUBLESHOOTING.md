# CodeQL Troubleshooting Guide

## Database Language Mismatch Error

### Problem
```
Error: Failed to run query: The query's dbscheme file name (go.dbscheme) did not match the database dbscheme (semmlecode.javascript.dbscheme).
```

### Cause
VS Code CodeQL extension has created a JavaScript database instead of a Go database for the project.

### Solutions

#### Option 1: Delete and Recreate Database
1. Open VS Code Command Palette (`Cmd+Shift+P` on macOS, `Ctrl+Shift+P` on Windows/Linux)
2. Run: `CodeQL: Remove Database from Workspace`
3. Select the incorrect database to remove it
4. Run: `CodeQL: Add Database from Folder`
5. Select the project root folder
6. Choose **Go** as the language when prompted

#### Option 2: Create Database via CLI
```bash
# Install CodeQL CLI if not already installed
# Download from: https://github.com/github/codeql-cli-binaries/releases

# Create Go database from project root
codeql database create --language=go --source-root=. codeql-database

# Add database to VS Code
# Use Command Palette: "CodeQL: Add Database from Folder"
# Select the created "codeql-database" folder
```

#### Option 3: Use GitHub Actions Database
1. Ensure the CodeQL GitHub Action has run successfully
2. Download the database artifact from a completed workflow run
3. Extract and add to VS Code workspace

### Verification
After adding the correct Go database:
1. Check that the database shows language as "Go" in VS Code
2. Try running one of the custom queries
3. Verify no database mismatch errors occur

### Configuration Files
The following files help ensure correct database creation:
- `.vscode/settings.json` - VS Code CodeQL settings
- `codeql-workspace.yml` - Project CodeQL configuration
- `.github/codeql/custom-queries/qlpack.yml` - Query package definition

### Auto-Detection
The project includes configuration to auto-detect Go language:
- `go.mod` file indicates Go project
- `.vscode/settings.json` specifies Go language preference
- `qlpack.yml` sets `extractor: go`

## Query Syntax Errors

### Testing Queries
Use the test script to validate query syntax:
```bash
./.github/codeql/test-queries.sh
```

### Common Issues
1. **Variable naming conflicts**: Avoid using CodeQL keywords as variable names
2. **Method availability**: Ensure methods exist on the target types
3. **Import statements**: Include `import go` at the top of queries

## Performance Issues

### Database Size
Large codebases may take time to create databases. Consider:
- Using GitHub Actions for database creation
- Excluding test files and dependencies
- Focusing analysis on specific paths

### Query Optimization
- Use precise predicates to reduce false positives
- Limit analysis scope with path filters
- Cache intermediate results where possible

## Support
For additional help:
- Check [CodeQL documentation](https://codeql.github.com/docs/)
- Review [GitHub Security Features](https://docs.github.com/en/code-security)
- Contact: [main@cybermonkey.net.au](mailto:main@cybermonkey.net.au)