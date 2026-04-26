package runner

import (
	"errors"
	"strings"
	"testing"
)

func TestMissingToolError_Format(t *testing.T) {
	tests := []struct {
		name     string
		err      *MissingToolError
		wantSubs []string
	}{
		{
			name: "all_fields",
			err: &MissingToolError{
				Tool:    "nuclei",
				Hint:    "reconforge tools install nuclei",
				DocsURL: "https://github.com/projectdiscovery/nuclei",
			},
			wantSubs: []string{
				`✗ tool "nuclei" not found in PATH`,
				"\nFix: reconforge tools install nuclei",
				"\nDocs: https://github.com/projectdiscovery/nuclei",
			},
		},
		{
			name: "tool_only",
			err:  &MissingToolError{Tool: "subfinder"},
			wantSubs: []string{
				`✗ tool "subfinder" not found in PATH`,
			},
		},
		{
			name: "tool_with_hint_no_docs",
			err: &MissingToolError{
				Tool: "httpx",
				Hint: "reconforge tools install httpx",
			},
			wantSubs: []string{
				`✗ tool "httpx" not found in PATH`,
				"\nFix: reconforge tools install httpx",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			for _, sub := range tt.wantSubs {
				if !strings.Contains(got, sub) {
					t.Errorf("Error() = %q\n  missing substring: %q", got, sub)
				}
			}
		})
	}
}

func TestMissingToolError_ErrorsAs(t *testing.T) {
	original := &MissingToolError{Tool: "nuclei"}
	wrapped := &someWrappedError{inner: original}

	var target *MissingToolError
	if !errors.As(wrapped, &target) {
		t.Fatal("errors.As failed to unwrap MissingToolError")
	}
	if target.Tool != "nuclei" {
		t.Errorf("got tool %q, want %q", target.Tool, "nuclei")
	}
}

type someWrappedError struct{ inner error }

func (e *someWrappedError) Error() string { return "wrapped: " + e.inner.Error() }
func (e *someWrappedError) Unwrap() error { return e.inner }
