package section2

import "github.com/pgharden/pgharden/internal/checker"

// Checks returns no checks on Windows — Section 2 requires Unix filesystem semantics.
func Checks() []checker.Check { return nil }
