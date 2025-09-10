module github.com/tekert/goetw/tools/etwread

go 1.24.5

require github.com/tekert/goetw v0.8.4-beta

require (
	github.com/goccy/go-json v0.10.5
	github.com/phuslu/log v1.0.120 // indirect
)

// The replace directive tells the Go tool to use the local copy
// of the library from the parent directory instead of downloading it.
replace github.com/tekert/goetw => ../..
