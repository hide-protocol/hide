//go:build !cgo

package hide

// This package is a cgo binding to a statically linked core: without cgo there
// is nothing to compile, and Go would otherwise report only "build constraints
// exclude all Go files". The undefined name below is the error message.
var _ = hide_needs_CGO_ENABLED_1_and_a_C_toolchain__see_sdk_go_README_md
