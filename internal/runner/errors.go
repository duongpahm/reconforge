package runner

import "fmt"

// MissingToolError indicates the requested tool is not available in PATH.
type MissingToolError struct {
	Tool string
}

func (e *MissingToolError) Error() string {
	return fmt.Sprintf("tool %q not found in PATH", e.Tool)
}
