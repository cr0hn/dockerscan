package logger

import (
	"io"
	"os"
	"testing"
)

// captureStderr redirects os.Stderr to a pipe, runs f, then returns what was written.
// The original os.Stderr is always restored via defer.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}

	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	f()

	w.Close()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	return string(out)
}

// resetGlobals returns a cleanup function that resets the package-level globals to false.
func resetGlobals() func() {
	return func() {
		VerboseEnabled = false
		DebugEnabled = false
	}
}

// --- Verbose tests ---

func TestVerbose_NothingWhenBothDisabled(t *testing.T) {
	defer resetGlobals()()
	VerboseEnabled = false
	DebugEnabled = false

	got := captureStderr(t, func() {
		Verbose("should not appear")
	})

	if got != "" {
		t.Errorf("expected empty stderr, got %q", got)
	}
}

func TestVerbose_WritesWhenVerboseEnabled(t *testing.T) {
	defer resetGlobals()()
	VerboseEnabled = true
	DebugEnabled = false

	got := captureStderr(t, func() {
		Verbose("mensaje")
	})

	want := "[VERBOSE] mensaje\n"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestVerbose_WritesWhenDebugEnabled(t *testing.T) {
	defer resetGlobals()()
	VerboseEnabled = false
	DebugEnabled = true

	got := captureStderr(t, func() {
		Verbose("mensaje")
	})

	want := "[VERBOSE] mensaje\n"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// --- Debug tests ---

func TestDebug_NothingWhenBothDisabled(t *testing.T) {
	defer resetGlobals()()
	VerboseEnabled = false
	DebugEnabled = false

	got := captureStderr(t, func() {
		Debug("should not appear")
	})

	if got != "" {
		t.Errorf("expected empty stderr, got %q", got)
	}
}

func TestDebug_NothingWhenOnlyVerboseEnabled(t *testing.T) {
	defer resetGlobals()()
	VerboseEnabled = true
	DebugEnabled = false

	got := captureStderr(t, func() {
		Debug("should not appear")
	})

	if got != "" {
		t.Errorf("expected empty stderr, got %q", got)
	}
}

func TestDebug_WritesWhenDebugEnabled(t *testing.T) {
	defer resetGlobals()()
	VerboseEnabled = false
	DebugEnabled = true

	got := captureStderr(t, func() {
		Debug("mensaje")
	})

	want := "[DEBUG] mensaje\n"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// --- Format / args tests ---

func TestVerbose_FormatWithArgs(t *testing.T) {
	defer resetGlobals()()
	VerboseEnabled = true
	DebugEnabled = false

	got := captureStderr(t, func() {
		Verbose("val=%d", 42)
	})

	want := "[VERBOSE] val=42\n"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}
