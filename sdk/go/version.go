//go:build cgo

package hide

import (
	"fmt"
	"strconv"
	"strings"
)

// BindingVersion is the HIDE release this package was written against.
//
// The archive in lib/ is copied there by hand, so it can be left behind by a
// newer checkout. A stale core would still link and would silently lack
// whatever the newer release enforces, so the package refuses to start unless
// the linked core reports exactly this major.minor.patch.
const BindingVersion = "0.9.1"

func init() {
	if err := checkCoreVersion(BindingVersion, Version()); err != nil {
		panic(err)
	}
}

// checkCoreVersion reports a mismatch between the version this binding was
// written against and the one the linked core reports. Only major.minor.patch
// is compared; a pre-release or build suffix is ignored.
func checkCoreVersion(binding, core string) error {
	want, okWant := parseVersion(binding)
	got, okGot := parseVersion(core)
	if okWant && okGot && want == got {
		return nil
	}
	return fmt.Errorf(
		"hide: this binding is version %s but the linked native core reports %q; "+
			"rebuild the core from the same checkout (cargo build --release -p hide-ffi) "+
			"and copy the static library into sdk/go/lib/ again",
		binding, core,
	)
}

// parseVersion reads the leading major.minor.patch of a version string.
func parseVersion(text string) ([3]uint64, bool) {
	var version [3]uint64
	if cut := strings.IndexAny(text, "-+"); cut >= 0 {
		text = text[:cut]
	}
	parts := strings.Split(text, ".")
	if len(parts) != 3 {
		return version, false
	}
	for index, part := range parts {
		// ParseUint accepts a leading "+", which is not a version.
		if part == "" || part[0] < '0' || part[0] > '9' {
			return version, false
		}
		number, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return version, false
		}
		version[index] = number
	}
	return version, true
}
