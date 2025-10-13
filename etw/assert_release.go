//go:build !debug

package etw

// In release builds, this function is an empty no-op.
func assert(condition bool, msg string, args ...any) {
    // Do nothing.
}