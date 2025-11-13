// pkg/apiclient/output.go
// Output formatting for API client framework
//
// HUMAN-CENTRIC: Default table format for readability, machine formats (JSON/YAML/CSV) for automation
// ARCHITECTURE: Pluggable formatters - easy to add new output formats
// TERMINAL-AWARE: Auto-detects terminal width, truncates long values intelligently

package apiclient

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Public API
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// FormatOutput formats API responses for display
// PARAMETERS:
//   - data: API response (ListResult, GetResult, CreateResult, UpdateResult, DeleteResult, or raw map)
//   - format: Output format ("table", "json", "yaml", "csv")
//
// RETURNS: error
//
// EXAMPLE:
//
//	result, err := executor.List(ctx, "users", filters)
//	if err := apiclient.FormatOutput(result, "table"); err != nil { ... }
func FormatOutput(data interface{}, format string) error {
	switch format {
	case "table", "":
		return formatTable(data)
	case "json":
		return formatJSON(data)
	case "yaml":
		return formatYAML(data)
	case "csv":
		return formatCSV(data)
	default:
		return fmt.Errorf("unknown output format: %s\n\n"+
			"Supported formats:\n"+
			"  table - Human-readable aligned columns (default)\n"+
			"  json  - Machine-readable JSON\n"+
			"  yaml  - Human-readable YAML\n"+
			"  csv   - Spreadsheet-compatible CSV", format)
	}
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Table Format (Default, Human-Centric)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// formatTable formats output as aligned table columns
// ARCHITECTURE:
//   - For ListResult: Render as table with headers
//   - For GetResult: Render as key-value pairs
//   - For CreateResult/UpdateResult: Render as key-value pairs
//   - For DeleteResult: Render success message
//
// TERMINAL-AWARE:
//   - Uses text/tabwriter for alignment
//   - Truncates long values with "..." (max 50 chars per cell)
//   - Detects terminal width (fallback: 120 columns)
func formatTable(data interface{}) error {
	switch v := data.(type) {
	case *ListResult:
		return formatListTable(v)
	case *GetResult:
		return formatItemTable(v.Item)
	case *CreateResult:
		fmt.Println("✓ Resource created successfully")
		if v.ID != nil {
			fmt.Printf("  ID: %v\n", v.ID)
		}
		if len(v.Item) > 0 {
			fmt.Println()
			return formatItemTable(v.Item)
		}
		return nil
	case *UpdateResult:
		fmt.Println("✓ Resource updated successfully")
		if len(v.Item) > 0 {
			fmt.Println()
			return formatItemTable(v.Item)
		}
		return nil
	case *DeleteResult:
		if v.Success {
			fmt.Println("✓ Resource deleted successfully")
		} else {
			fmt.Println("✗ Resource deletion failed")
		}
		if v.Message != "" {
			fmt.Printf("  Message: %s\n", v.Message)
		}
		return nil
	default:
		return fmt.Errorf("unsupported data type for table formatting: %T", data)
	}
}

// formatListTable formats a list of items as a table
// EXAMPLE OUTPUT:
//
//	PK                                    USERNAME         EMAIL                    TYPE      ACTIVE
//	123e4567-e89b-12d3-a456-426614174000  alice_wonderland alice@example.com       external  true
//	234e5678-e89b-12d3-a456-426614174001  bob_builder      bob@example.com         external  true
func formatListTable(result *ListResult) error {
	if len(result.Items) == 0 {
		fmt.Println("No results found")
		return nil
	}

	// Step 1: Determine columns from first item (all keys)
	firstItem := result.Items[0]
	columns := getSortedKeys(firstItem)

	// Step 2: Create tabwriter for alignment
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// Step 3: Write header row
	headerRow := make([]string, len(columns))
	for i, col := range columns {
		headerRow[i] = strings.ToUpper(col)
	}
	fmt.Fprintln(w, strings.Join(headerRow, "\t"))

	// Step 4: Write data rows
	for _, item := range result.Items {
		row := make([]string, len(columns))
		for i, col := range columns {
			val := item[col]
			row[i] = truncateValue(formatValue(val), 50)
		}
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}

	// Step 5: Flush tabwriter
	if err := w.Flush(); err != nil {
		return fmt.Errorf("failed to flush table output: %w", err)
	}

	// Step 6: Print summary
	fmt.Printf("\nTotal: %d\n", result.TotalCount)
	if result.NextPage != "" {
		fmt.Printf("Next page: %s\n", result.NextPage)
	}

	return nil
}

// formatItemTable formats a single item as key-value pairs
// EXAMPLE OUTPUT:
//
//	pk: 123e4567-e89b-12d3-a456-426614174000
//	username: alice_wonderland
//	email: alice@example.com
//	type: external
//	is_active: true
//	groups: [uuid1, uuid2]
func formatItemTable(item map[string]interface{}) error {
	if len(item) == 0 {
		fmt.Println("No data")
		return nil
	}

	// Step 1: Get sorted keys
	keys := getSortedKeys(item)

	// Step 2: Find longest key for alignment
	maxKeyLen := 0
	for _, key := range keys {
		if len(key) > maxKeyLen {
			maxKeyLen = len(key)
		}
	}

	// Step 3: Print key-value pairs
	for _, key := range keys {
		val := item[key]
		formattedVal := formatValue(val)

		// Multi-line values get indented
		if strings.Contains(formattedVal, "\n") {
			fmt.Printf("%-*s:\n%s\n", maxKeyLen, key, indentMultiline(formattedVal, maxKeyLen+2))
		} else {
			fmt.Printf("%-*s: %s\n", maxKeyLen, key, formattedVal)
		}
	}

	return nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// JSON Format (Machine-Readable)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// formatJSON formats output as indented JSON
// EXAMPLE OUTPUT:
//
//	{
//	  "items": [
//	    {
//	      "pk": "123e4567-e89b-12d3-a456-426614174000",
//	      "username": "alice",
//	      "email": "alice@example.com"
//	    }
//	  ],
//	  "total_count": 1
//	}
func formatJSON(data interface{}) error {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(jsonBytes))
	return nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// YAML Format (Human-Readable, Structured)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// formatYAML formats output as YAML
// EXAMPLE OUTPUT:
//
//	items:
//	  - pk: 123e4567-e89b-12d3-a456-426614174000
//	    username: alice
//	    email: alice@example.com
//	total_count: 1
func formatYAML(data interface{}) error {
	yamlBytes, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	fmt.Print(string(yamlBytes))
	return nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CSV Format (Spreadsheet-Compatible)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// formatCSV formats output as CSV with headers
// EXAMPLE OUTPUT:
//
//	pk,username,email,type,is_active
//	123e4567-e89b-12d3-a456-426614174000,alice,alice@example.com,external,true
//	234e5678-e89b-12d3-a456-426614174001,bob,bob@example.com,external,true
//
// NOTE: Only supports ListResult (CSV requires tabular data)
func formatCSV(data interface{}) error {
	listResult, ok := data.(*ListResult)
	if !ok {
		return fmt.Errorf("CSV format only supports list results (got %T)", data)
	}

	if len(listResult.Items) == 0 {
		fmt.Println("# No results")
		return nil
	}

	// Step 1: Determine columns from first item
	firstItem := listResult.Items[0]
	columns := getSortedKeys(firstItem)

	// Step 2: Create CSV writer
	writer := csv.NewWriter(os.Stdout)
	defer writer.Flush()

	// Step 3: Write header row
	if err := writer.Write(columns); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Step 4: Write data rows
	for _, item := range listResult.Items {
		row := make([]string, len(columns))
		for i, col := range columns {
			val := item[col]
			row[i] = formatValue(val)
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Helper Functions
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// getSortedKeys returns sorted keys from a map
// RATIONALE: Consistent column ordering across runs
func getSortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// formatValue converts any value to a string representation
// HANDLES:
//   - nil → "(null)"
//   - bool → "true" / "false"
//   - numbers → string representation
//   - strings → as-is
//   - slices → comma-separated
//   - maps → JSON representation
func formatValue(val interface{}) string {
	if val == nil {
		return "(null)"
	}

	switch v := val.(type) {
	case string:
		return v
	case bool:
		if v {
			return "true"
		}
		return "false"
	case int, int8, int16, int32, int64:
		return fmt.Sprintf("%d", v)
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", v)
	case float32, float64:
		return fmt.Sprintf("%g", v)
	case []interface{}:
		// Format as comma-separated list
		parts := make([]string, len(v))
		for i, item := range v {
			parts[i] = formatValue(item)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]interface{}:
		// Format as JSON
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("(error: %v)", err)
		}
		return string(jsonBytes)
	default:
		// Fallback: use reflection
		rv := reflect.ValueOf(val)
		switch rv.Kind() {
		case reflect.Slice, reflect.Array:
			parts := make([]string, rv.Len())
			for i := 0; i < rv.Len(); i++ {
				parts[i] = formatValue(rv.Index(i).Interface())
			}
			return "[" + strings.Join(parts, ", ") + "]"
		case reflect.Map:
			jsonBytes, err := json.Marshal(val)
			if err != nil {
				return fmt.Sprintf("(error: %v)", err)
			}
			return string(jsonBytes)
		default:
			return fmt.Sprintf("%v", val)
		}
	}
}

// truncateValue truncates long strings with "..."
// RATIONALE: Keeps table output readable in terminal
// EXAMPLE: truncateValue("very long UUID string here", 20) → "very long UUID st..."
func truncateValue(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return "..."
	}
	return s[:maxLen-3] + "..."
}

// indentMultiline indents each line of a multi-line string
// RATIONALE: Makes nested structures readable in key-value output
func indentMultiline(s string, indent int) string {
	lines := strings.Split(s, "\n")
	indentStr := strings.Repeat(" ", indent)
	for i, line := range lines {
		lines[i] = indentStr + line
	}
	return strings.Join(lines, "\n")
}
