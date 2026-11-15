//go:build cgo && !(linux || darwin || windows)

package hide

// hide.go carries link flags for Linux, macOS and Windows only. Anywhere else
// the build would otherwise end in a page of undefined references from the
// linker; the undefined name below is the error message instead.
var _ = hide_links_only_on_linux_darwin_and_windows__see_sdk_go_README_md
