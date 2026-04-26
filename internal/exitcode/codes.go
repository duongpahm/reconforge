package exitcode

import (
	"errors"
	"os"
	"strings"
)

const (
	OK            = 0
	UsageError    = 1
	ScanFailed    = 2
	CriticalFound = 3
	ToolMissing   = 4
	ConfigInvalid = 5
	ScopeInvalid  = 6
	Interrupted   = 130
)

type codedError struct {
	code int
	err  error
}

func (e *codedError) Error() string {
	return e.err.Error()
}

func (e *codedError) Unwrap() error {
	return e.err
}

func wrap(code int, err error) error {
	if err == nil {
		return nil
	}
	return &codedError{code: code, err: err}
}

func Usage(err error) error {
	return wrap(UsageError, err)
}

func Scan(err error) error {
	return wrap(ScanFailed, err)
}

func Config(err error) error {
	return wrap(ConfigInvalid, err)
}

func Scope(err error) error {
	return wrap(ScopeInvalid, err)
}

func MissingTool(err error) error {
	return wrap(ToolMissing, err)
}

func Code(err error) int {
	if err == nil {
		return OK
	}

	var coded *codedError
	if errors.As(err, &coded) {
		return coded.code
	}

	if errors.Is(err, os.ErrInvalid) {
		return UsageError
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "unknown flag"),
		strings.Contains(msg, "accepts"),
		strings.Contains(msg, "requires at least"),
		strings.Contains(msg, "requires exactly"),
		strings.Contains(msg, "usage"):
		return UsageError
	case strings.Contains(msg, "config"),
		strings.Contains(msg, "profile"):
		return ConfigInvalid
	case strings.Contains(msg, "scope"):
		return ScopeInvalid
	case strings.Contains(msg, "not found in $path"),
		strings.Contains(msg, "executable file not found"):
		return ToolMissing
	default:
		return ScanFailed
	}
}
