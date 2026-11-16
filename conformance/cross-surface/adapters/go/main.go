// Drives the Go SDK for the cross-surface interop matrix. Two commands:
//
//	hide-adapter encrypt <public-key> <plaintext> <out-container>
//	hide-adapter decrypt <secret-key> <container> <out-plaintext>
//
// The cgo build needs `sdk/go/include/hide.h` and `sdk/go/lib/libhide_ffi.a`
// beside the package, exactly as a user of the SDK does; see sdk/go/README.md.
package main

import (
	"fmt"
	"os"

	hide "github.com/hide-protocol/hide/sdk/go"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: hide-adapter encrypt|decrypt <key> <input> <output>")
		os.Exit(2)
	}
	command, keyPath, inputPath, outputPath := os.Args[1], os.Args[2], os.Args[3], os.Args[4]

	key, err := os.ReadFile(keyPath)
	check(err)
	input, err := os.ReadFile(inputPath)
	check(err)

	// A protected key file would need a passphrase, which a cross-surface vector
	// never carries; the matrix uses raw seeds.
	switch command {
	case "encrypt":
		container, err := hide.Encrypt(input, [][]byte{key}, hide.Options{Filename: "go.txt"})
		check(err)
		check(os.WriteFile(outputPath, container, 0o600))
	case "decrypt":
		secret, err := hide.LoadKey(key, "")
		check(err)
		defer secret.Close()
		opened, err := hide.Decrypt(input, secret)
		check(err)
		check(os.WriteFile(outputPath, opened.Data, 0o600))
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", command)
		os.Exit(2)
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
