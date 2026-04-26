package ui

import (
	"os"

	"golang.org/x/term"
)

var (
	stdoutTTY = func() bool {
		return term.IsTerminal(int(os.Stdout.Fd()))
	}
	stderrTTY = func() bool {
		return term.IsTerminal(int(os.Stderr.Fd()))
	}
)

// IsTTY reports whether stdout is an interactive terminal.
func IsTTY() bool {
	return stdoutTTY()
}

// IsStderrTTY reports whether stderr is an interactive terminal.
func IsStderrTTY() bool {
	return stderrTTY()
}

// ColorEnabled reports whether ANSI color output should be used.
func ColorEnabled() bool {
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled {
		return false
	}
	return IsTTY()
}
