package section2

// Section 2 checks require Unix filesystem semantics (permissions, ownership)
// and are not applicable on Windows. All checks self-register only on
// Unix-like systems via the build tag on section2.go.
