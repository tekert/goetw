module github.com/tekert/goetw/tools/etwdump

go 1.24

require (
	github.com/0xrawsec/golang-utils v1.3.2
	github.com/tekert/goetw v0.6.2
)

require github.com/phuslu/log v1.0.119 // indirect

// The replace directive tells the Go tool to use the local copy
// of the library from the parent directory instead of downloading it.
replace github.com/tekert/goetw => ../..
