// Package identity defines the matching rules shared by baseline storage and detection.
package identity

import "path/filepath"

// Library returns the canonical path identity used by profiles. Basenames alone
// are intentionally insufficient to equate two providers.
func Library(path string) string { return filepath.Clean(path) }

// SameLibrary compares library paths using the same identity used by profiles.
func SameLibrary(a, b string) bool { return a == b || Library(a) == Library(b) }
