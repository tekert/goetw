module debug_etw

go 1.24.5

replace github.com/tekert/goetw => ../

require (
	github.com/goccy/go-json v0.10.5
	github.com/tekert/goetw v0.9.2
)

require github.com/phuslu/log v1.0.120 // indirect
