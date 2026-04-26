package exitcode

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestCode_Wrappers(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"nil", nil, OK},
		{"usage", Usage(errors.New("bad flag")), UsageError},
		{"scan_failed", Scan(errors.New("scan err")), ScanFailed},
		{"config", Config(errors.New("invalid config")), ConfigInvalid},
		{"scope", Scope(errors.New("bad scope")), ScopeInvalid},
		{"missing_tool", MissingTool(errors.New("nuclei missing")), ToolMissing},
		{"interrupt", Interrupt(errors.New("ctrl+c")), Interrupted},
		{"critical_finding", CriticalFinding(errors.New("found rce")), CriticalFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Code(tt.err)
			if got != tt.wantCode {
				t.Errorf("Code(%v) = %d, want %d", tt.err, got, tt.wantCode)
			}
		})
	}
}

func TestCode_WrappedContextCanceled(t *testing.T) {
	// Real-world flow: scan returns context.Canceled, main wraps it via Interrupt().
	// Exit code must be 130 so shell scripts can detect SIGINT.
	wrapped := Interrupt(fmt.Errorf("scan interrupted: %w", context.Canceled))
	if got := Code(wrapped); got != Interrupted {
		t.Errorf("interrupted exit code = %d, want %d", got, Interrupted)
	}
}

func TestCode_StringFallback(t *testing.T) {
	// Untagged errors should fall back to substring matching.
	tests := []struct {
		name     string
		errMsg   string
		wantCode int
	}{
		{"unknown_flag", "unknown flag --foo", UsageError},
		{"scope_invalid", "scope file invalid", ScopeInvalid},
		{"executable_not_found", "exec: \"nuclei\": executable file not found in $PATH", ToolMissing},
		{"generic", "something failed", ScanFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Code(errors.New(tt.errMsg))
			if got != tt.wantCode {
				t.Errorf("Code(%q) = %d, want %d", tt.errMsg, got, tt.wantCode)
			}
		})
	}
}
