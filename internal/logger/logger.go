package logger

import (
	"fmt"
	"os"
)

var (
	// VerboseEnabled enables verbose output (user-facing progress messages)
	VerboseEnabled bool

	// DebugEnabled enables debug output (developer-facing technical details)
	// When DebugEnabled is true, VerboseEnabled is also implicitly active.
	DebugEnabled bool
)

// Verbose prints a progress message to stderr when verbose or debug mode is active.
// Use for user-facing messages like "Running scanner X..." or "Pulling image Y...".
func Verbose(format string, args ...any) {
	if VerboseEnabled || DebugEnabled {
		fmt.Fprintf(os.Stderr, "[VERBOSE] "+format+"\n", args...)
	}
}

// Debug prints a technical debug message to stderr when debug mode is active.
// Use for developer-facing messages like silenced errors, internal state, etc.
func Debug(format string, args ...any) {
	if DebugEnabled {
		fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
	}
}
