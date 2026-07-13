package version

import "testing"

func TestCompare(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int
	}{
		// Basic numeric ordering.
		{"equal", "1.0.0", "1.0.0", 0},
		{"patch less", "1.0.0", "1.0.1", -1},
		{"patch greater", "1.0.1", "1.0.0", 1},
		{"minor less", "1.0.0", "1.1.0", -1},
		{"major greater", "2.0.0", "1.9.9", 1},

		// dpkg semantics: absent trailing component is smaller.
		{"1.0 < 1.0.0", "1.0", "1.0.0", -1},
		{"1.0.0 > 1.0", "1.0.0", "1.0", 1},

		// Documented FP-risk case: 3.0.0 sorts after a bare 3.0.
		{"3.0.0 > 3.0", "3.0.0", "3.0", 1},

		// Leading zeros are ignored (numeric compare).
		{"1.05 == 1.5", "1.05", "1.5", 0},
		{"01 == 1", "01", "1", 0},
		{"1.0.09 < 1.0.10", "1.0.09", "1.0.10", -1},

		// Tilde sorts before everything, including end-of-part.
		{"tilde before release", "1.0.0~rc93", "1.0.0", -1},
		{"release after tilde", "1.0.0", "1.0.0~rc93", 1},
		{"rc92 < rc93", "1.0.0~rc92", "1.0.0~rc93", -1},
		{"tilde before empty part", "1.0~", "1.0", -1},

		// Letters sort before non-letters; uppercase before lowercase (ASCII).
		{"1.0B < 1.0a", "1.0B", "1.0a", -1},
		{"1.0a > 1.0", "1.0a", "1.0", 1},
		{"letter before plus", "1.0a", "1.0+", -1},

		// Long digit runs must not overflow (no strconv).
		{"git run greater than base", "1.0+git20240101223344", "1.0", 1},
		{"git run diff last digit", "1.0+git20240101223344", "1.0+git20240101223345", -1},
		{"huge equal runs", "20240101223344556677", "20240101223344556677", 0},

		// OpenSSL letter-suffixed releases.
		{"openssl 1.0.1e < 1.0.1g", "1.0.1e", "1.0.1g", -1},
		{"openssl 1.0.1g > 1.0.1f", "1.0.1g", "1.0.1f", 1},

		// Real bounds used in the range-membership tests below.
		{"1.1.4 > rc93 start", "1.1.4", "1.0.0~rc93", 1},
		{"1.1.4 < 1.1.12", "1.1.4", "1.1.12", -1},
		{"1.1.12 == 1.1.12", "1.1.12", "1.1.12", 0},
		{"2.0~rc1 < 2.0", "2.0~rc1", "2.0", -1},
		{"3.5.0~rc1 < 3.5.0", "3.5.0~rc1", "3.5.0", -1},

		// Empty operands.
		{"empty less", "", "1.0", -1},
		{"empty greater", "1.0", "", 1},
		{"both empty", "", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Compare(tt.a, tt.b); got != tt.want {
				t.Errorf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
			// Comparison must be antisymmetric.
			if got := Compare(tt.b, tt.a); got != -tt.want {
				t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", tt.b, tt.a, got, -tt.want)
			}
		})
	}
}

func TestNormalizeInstalled(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		source string
		want   string
	}{
		{"strip epoch", "1:1.2.14-1", "dpkg", "1.2.14"},
		{"strip multidigit epoch", "100:1.2.3-4", "dpkg", "1.2.3"},
		{"non-numeric colon kept", "http://x", "dpkg", "http://x"},
		{"dpkg ubuntu revision", "3.0.2-0ubuntu1.18", "dpkg", "3.0.2"},
		{"dpkg bash revision", "5.1-6ubuntu1.1", "dpkg", "5.1"},
		{"dpkg native no hyphen", "2.37.2", "dpkg", "2.37.2"},
		{"dpkg rc before revision", "1.0.0-rc92-1", "dpkg", "1.0.0~rc92"},
		{"apk rc and revision", "3.5.0_rc1-r0", "apk", "3.5.0~rc1"},
		{"apk revision only", "1.2.3-r15", "apk", "1.2.3"},
		{"apk no revision", "1.2.3", "apk", "1.2.3"},
		{"dpkg prerelease hyphen", "2.0-rc1", "dpkg", "2.0~rc1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeInstalled(tt.in, tt.source); got != tt.want {
				t.Errorf("NormalizeInstalled(%q, %q) = %q, want %q", tt.in, tt.source, got, tt.want)
			}
		})
	}
}

func TestNormalizeRangeValue(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"1.0.0-rc93", "1.0.0~rc93"},
		{"1.0.0_beta2", "1.0.0~beta2"},
		{"2.0-rc1", "2.0~rc1"},
		{"1.0-preview1", "1.0~preview1"},
		{"1.0-rc", "1.0~rc"},
		// Keyword lowercased so 1.0-RC1 equality-matches a CVE bound 1.0-rc1.
		{"1.0-RC1", "1.0~rc1"},
		{"1.0_Beta2", "1.0~beta2"},
		// Anchored: "pre" not followed by digit/dot/end is left alone.
		{"1.0-pretty", "1.0-pretty"},
		// Post-release markers are not prereleases.
		{"1.0_p20240101", "1.0_p20240101"},
		{"1.0_git1234", "1.0_git1234"},
		{"1.2.14", "1.2.14"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := NormalizeRangeValue(tt.in); got != tt.want {
				t.Errorf("NormalizeRangeValue(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestRangeMembership exercises the end-to-end pipeline: normalize the installed
// version and the range bounds, then decide membership with Compare. This is the
// behavior the scanner relies on.
func TestRangeMembership(t *testing.T) {
	// inRange reports whether installed is within [start, end) after
	// normalization (start including, end excluding).
	inRange := func(installed, source, start, end string) bool {
		iv := NormalizeInstalled(installed, source)
		lo := NormalizeRangeValue(start)
		hi := NormalizeRangeValue(end)
		return Compare(iv, lo) >= 0 && Compare(iv, hi) < 0
	}

	tests := []struct {
		name              string
		installed, source string
		start, end        string
		want              bool
	}{
		{"1.0.0 in [1.0.0-rc93,1.1.12)", "1.0.0", "dpkg", "1.0.0-rc93", "1.1.12", true},
		{"1.0.0-rc92 not in [1.0.0-rc93,1.1.12)", "1.0.0-rc92", "dpkg", "1.0.0-rc93", "1.1.12", false},
		{"1.1.4 in [1.0.0-rc93,1.1.12)", "1.1.4", "dpkg", "1.0.0-rc93", "1.1.12", true},
		{"1.1.12 not in [1.0.0-rc93,1.1.12)", "1.1.12", "dpkg", "1.0.0-rc93", "1.1.12", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inRange(tt.installed, tt.source, tt.start, tt.end); got != tt.want {
				t.Errorf("inRange(%q,%q,[%q,%q)) = %v, want %v",
					tt.installed, tt.source, tt.start, tt.end, got, tt.want)
			}
		})
	}

	// Epoch strip: installed "1:1.2.14-1" must equal the exact range value
	// "1.2.14" (both bounds including => equality match).
	iv := NormalizeInstalled("1:1.2.14-1", "dpkg")
	if Compare(iv, NormalizeRangeValue("1.2.14")) != 0 {
		t.Errorf("epoch-stripped %q should equal exact bound 1.2.14", iv)
	}
}

// TestRangeMembership_LessThanBounds covers "< X" style ranges (unbounded
// start, excluding end) used by the fixed-in-version logic.
func TestRangeMembership_LessThanBounds(t *testing.T) {
	vulnerable := func(installed, source, end string) bool {
		iv := NormalizeInstalled(installed, source)
		hi := NormalizeRangeValue(end)
		return Compare(iv, hi) < 0
	}

	if !vulnerable("2.0-rc1", "dpkg", "2.0") {
		t.Error("2.0-rc1 should be < 2.0 (vulnerable)")
	}
	if !vulnerable("3.5.0_rc1-r0", "apk", "3.5.0") {
		t.Error("3.5.0_rc1-r0 should be < 3.5.0 (vulnerable)")
	}
	if vulnerable("2.0", "dpkg", "2.0") {
		t.Error("2.0 should not be < 2.0")
	}
}
