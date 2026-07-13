// Package version implements Debian dpkg-style version comparison and the
// normalization pipeline dockerscan applies before comparing an installed
// package version against a CVE version range.
//
// The comparator is a pure port of the algorithm in Debian Policy 5.6.12
// (the same one dpkg --compare-versions uses). It operates on PRE-NORMALIZED
// strings: callers must run NormalizeInstalled / NormalizeRangeValue first so
// that epochs, distro revisions and prerelease separators are handled
// consistently on both sides of a comparison.
package version

import (
	"regexp"
	"strings"
)

// preReleaseSepRe matches a prerelease keyword introduced by a "-" or "_"
// separator and immediately followed by a digit, a dot, or the end of the
// string. Only the separator is rewritten to "~" (see NormalizeRangeValue);
// the keyword and the boundary character are preserved.
//
// Go's regexp (RE2) has no lookahead, so the boundary is a real capturing
// group ([0-9.]|$) that the replacement re-emits. The keyword list is
// deliberately narrow: post-release markers such as "_p", "_git" and "-rN"
// must NOT be treated as prereleases.
var preReleaseSepRe = regexp.MustCompile(`(?i)[-_](rc|alpha|beta|pre(?:view)?)([0-9.]|$)`)

// apkRevisionRe matches a trailing Alpine package revision ("-r0", "-r15").
var apkRevisionRe = regexp.MustCompile(`-r[0-9]+$`)

// Compare returns -1, 0 or 1 as a orders before, equal to, or after b using the
// dpkg upstream-version algorithm. Inputs are assumed already normalized.
//
// The strings are walked left to right, alternating a longest run of
// non-digit characters and a longest run of digits. Non-digit runs compare
// byte-wise under order() (tilde before everything, letters before
// non-letters). Digit runs compare numerically with leading zeros stripped and
// the longer run winning ties — no integer parsing, so arbitrarily long git
// timestamp runs never overflow.
func Compare(a, b string) int {
	i, j := 0, 0
	la, lb := len(a), len(b)

	for i < la || j < lb {
		// Compare the leading non-digit run of each side.
		for (i < la && !isDigit(a[i])) || (j < lb && !isDigit(b[j])) {
			ac, bc := 0, 0
			if i < la {
				ac = order(a[i])
			}
			if j < lb {
				bc = order(b[j])
			}
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}

		// Skip leading zeros so digit runs compare by numeric value.
		for i < la && a[i] == '0' {
			i++
		}
		for j < lb && b[j] == '0' {
			j++
		}

		// Compare the digit runs. firstDiff records the first differing digit;
		// it only decides the result if both runs have the same length.
		firstDiff := 0
		for i < la && isDigit(a[i]) && j < lb && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < la && isDigit(a[i]) {
			return 1
		}
		if j < lb && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}

	return 0
}

// order maps a byte to its dpkg sort rank within a non-digit run. A tilde sorts
// before everything (including the end of a part, rank 0), letters sort by
// their ASCII value, and any other non-letter sorts after letters. A digit or
// the end-of-string (passed as the zero value) has rank 0.
func order(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// NormalizeInstalled normalizes an installed package version for comparison. The
// pipeline order is load-bearing:
//
//  1. Strip a leading numeric epoch ("1:1.2.14-1" -> "1.2.14-1").
//  2. Rewrite prerelease separators to "~" so "1.0.0-rc92" sorts before
//     "1.0.0" ("1.0.0-rc92" -> "1.0.0~rc92"). Done BEFORE step 3 so the rc
//     hyphen is consumed and not mistaken for a distro revision.
//  3. Strip the distro revision: the trailing "-rN" for apk, otherwise the
//     part after the LAST remaining hyphen (dpkg). Only the upstream version
//     is compared, so a distro's backported fix in the revision is invisible
//     here — callers disclose that separately.
func NormalizeInstalled(v, source string) string {
	v = stripEpoch(v)
	v = NormalizeRangeValue(v)

	if source == "apk" {
		return apkRevisionRe.ReplaceAllString(v, "")
	}
	if idx := lastIndexByte(v, '-'); idx > 0 {
		return v[:idx]
	}
	return v
}

// NormalizeRangeValue normalizes a CVE range bound. CVE values carry no epoch or
// distro revision and their hyphens are meaningful, so only the prerelease
// separator rewrite (step 2) applies. The keyword is lowercased so an installed
// "1.0-RC1" equality-matches a CVE bound "1.0-rc1" (Compare is case-sensitive
// ASCII).
//
// Known limitation (accepted): a prerelease keyword followed by a further
// hyphenated part — e.g. dpkg "1.0-beta-1" — fails the boundary group, keeps
// its hyphen, and the upstream part then sorts AFTER "1.0" instead of before.
func NormalizeRangeValue(v string) string {
	return preReleaseSepRe.ReplaceAllStringFunc(v, func(m string) string {
		sub := preReleaseSepRe.FindStringSubmatch(m)
		return "~" + strings.ToLower(sub[1]) + sub[2]
	})
}

// DistroRevision returns the distro-specific revision that NormalizeInstalled
// strips from v: the trailing "rN" for apk, otherwise the part after the last
// remaining hyphen for dpkg. It returns "" when there is no revision. This is
// disclosed to users so they know the comparison ignored a possible backport.
func DistroRevision(v, source string) string {
	v = stripEpoch(v)
	v = NormalizeRangeValue(v)
	if source == "apk" {
		if m := apkRevisionRe.FindString(v); m != "" {
			return m[1:] // drop the leading '-'
		}
		return ""
	}
	if idx := lastIndexByte(v, '-'); idx > 0 {
		return v[idx+1:]
	}
	return ""
}

// stripEpoch removes a leading "<digits>:" epoch prefix. A malformed
// multi-epoch value ("1:2:3") only loses its first epoch; dpkg allows a single
// epoch, so the leftover ':' simply compares at non-letter rank.
func stripEpoch(v string) string {
	idx := -1
	for i := 0; i < len(v); i++ {
		if v[i] == ':' {
			idx = i
			break
		}
		if !isDigit(v[i]) {
			return v
		}
	}
	if idx > 0 {
		return v[idx+1:]
	}
	return v
}

func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}
