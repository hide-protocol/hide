/*
 * The one place the Go binding includes the C API from.
 *
 * include/hide.h and lib/libhide_ffi.a are build outputs of the Rust core and
 * are not committed, so a plain `go get` of this module cannot compile. This
 * wrapper turns the bare "hide.h: No such file or directory" into an
 * explanation of what to do.
 */
#ifndef HIDE_GO_CORE_H
#define HIDE_GO_CORE_H

#if defined(__has_include)
#  if __has_include("hide.h")
#    include "hide.h"
#  else
#    error "sdk/go/include/hide.h is missing. This package links the HIDE core statically and the core is not committed: clone https://github.com/hide-protocol/hide, run `cargo build --release -p hide-ffi` (on Windows add `--target x86_64-pc-windows-gnu`), then copy crates/hide-ffi/include/hide.h into sdk/go/include/ and libhide_ffi.a into sdk/go/lib/. See sdk/go/README.md, section Install."
#  endif
#else
#  include "hide.h"
#endif

#endif /* HIDE_GO_CORE_H */
