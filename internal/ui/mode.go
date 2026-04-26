package ui

import (
	"os"

	"golang.org/x/term"
)

// IsTTY reports whether stdout is an interactive terminal.
func IsTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// IsStderrTTY reports whether stderr is an interactive terminal.
func IsStderrTTY() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}
