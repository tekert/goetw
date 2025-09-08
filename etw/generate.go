package etw

// -- Generate GO Kernel definitions from C++ MOF definitions
//go:generate go run ../internal/mofgen/cmd/main.go

// -- Generate stringer for TdhOutType and TdhInType (for debug messages)
//go:generate stringer -type=TdhOutType,TdhInType -output=gen_tdh_strings.go
