//go:build debug

package etw

import "fmt"

// In debug builds, this function will panic if the condition is false.
func assert(condition bool, msg string, args ...any) {
	if !condition {
		panic(fmt.Sprintf(msg, args...))
	}
}
