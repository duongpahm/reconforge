package runner

import (
	"fmt"
	"strings"
)

// MissingToolError indicates the requested tool is not available in PATH.
type MissingToolError struct {
	Tool    string
	Hint    string
	DocsURL string
}

func (e *MissingToolError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "✗ tool %q not found in PATH", e.Tool)
	if e.Hint != "" {
		fmt.Fprintf(&b, "\nFix: %s", e.Hint)
	}
	if e.DocsURL != "" {
		fmt.Fprintf(&b, "\nDocs: %s", e.DocsURL)
	}
	return b.String()
}
