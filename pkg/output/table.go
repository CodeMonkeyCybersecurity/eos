// Package output provides table formatting utilities for consistent terminal output
package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
)

// TableWriter provides a fluent interface for building and displaying tables
type TableWriter struct {
	writer     *tabwriter.Writer
	headers    []string
	rows       [][]string
	separator  string
	showBorder bool
}

// NewTable creates a new table writer that outputs to stdout
func NewTable() *TableWriter {
	return NewTableTo(os.Stdout)
}

// NewTableTo creates a new table writer that outputs to the specified writer
func NewTableTo(w io.Writer) *TableWriter {
	return &TableWriter{
		writer:     tabwriter.NewWriter(w, 0, 0, 2, ' ', 0),
		separator:  "-",
		showBorder: true,
	}
}

// WithHeaders sets the column headers for the table
func (t *TableWriter) WithHeaders(headers ...string) *TableWriter {
	t.headers = headers
	return t
}

// WithSeparator sets the character used for horizontal separators
func (t *TableWriter) WithSeparator(sep string) *TableWriter {
	t.separator = sep
	return t
}

// WithBorder controls whether to show table borders
func (t *TableWriter) WithBorder(show bool) *TableWriter {
	t.showBorder = show
	return t
}

// AddRow adds a row of data to the table
func (t *TableWriter) AddRow(values ...string) *TableWriter {
	t.rows = append(t.rows, values)
	return t
}

// AddRows adds multiple rows of data to the table
func (t *TableWriter) AddRows(rows [][]string) *TableWriter {
	t.rows = append(t.rows, rows...)
	return t
}

// Render outputs the table to the writer
func (t *TableWriter) Render() error {
	if t.showBorder && len(t.headers) > 0 {
		// Calculate total width for border
		totalWidth := 0
		for _, h := range t.headers {
			totalWidth += len(h) + 4 // padding
		}
		fmt.Fprintln(t.writer, strings.Repeat(t.separator, totalWidth))
	}

	// Write headers
	if len(t.headers) > 0 {
		fmt.Fprintln(t.writer, strings.Join(t.headers, "\t"))
		if t.showBorder {
			// Separator line under headers
			separators := make([]string, len(t.headers))
			for i, h := range t.headers {
				separators[i] = strings.Repeat(t.separator, len(h))
			}
			fmt.Fprintln(t.writer, strings.Join(separators, "\t"))
		}
	}

	// Write rows
	for _, row := range t.rows {
		fmt.Fprintln(t.writer, strings.Join(row, "\t"))
	}

	return t.writer.Flush()
}

// SimpleTable creates and renders a simple table in one call
func SimpleTable(headers []string, rows [][]string) error {
	return NewTable().
		WithHeaders(headers...).
		AddRows(rows).
		Render()
}

// KeyValueTable renders a simple key-value table
func KeyValueTable(data map[string]string) error {
	table := NewTable().WithHeaders("Key", "Value")
	for k, v := range data {
		table.AddRow(k, v)
	}
	return table.Render()
}
