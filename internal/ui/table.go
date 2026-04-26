package ui

import (
	"fmt"
	"strings"
)

// Table represents an ASCII table for terminal output.
type Table struct {
	Headers []string
	Rows    [][]string
}

// NewTable creates a new Table instance.
func NewTable(headers []string) *Table {
	return &Table{
		Headers: headers,
		Rows:    make([][]string, 0),
	}
}

// AddRow adds a row to the table.
func (t *Table) AddRow(row []string) {
	t.Rows = append(t.Rows, row)
}

// Render prints the table to stdout.
func (t *Table) Render() {
	if len(t.Headers) == 0 {
		return
	}

	// Calculate column widths
	colWidths := make([]int, len(t.Headers))
	for i, h := range t.Headers {
		colWidths[i] = len(h)
	}
	for _, row := range t.Rows {
		for i, cell := range row {
			if i < len(colWidths) && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	// Print headers
	for i, h := range t.Headers {
		fmt.Printf("%-*s", colWidths[i]+2, h)
	}
	fmt.Println()

	// Print separator
	for i := range t.Headers {
		fmt.Print(strings.Repeat("-", colWidths[i]))
		fmt.Print("  ")
	}
	fmt.Println()

	// Print rows
	for _, row := range t.Rows {
		for i, cell := range row {
			if i < len(colWidths) {
				fmt.Printf("%-*s", colWidths[i]+2, cell)
			}
		}
		fmt.Println()
	}
}
