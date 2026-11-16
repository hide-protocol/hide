// A separate module with a filesystem replace, so the adapter always builds
// against the SDK in this checkout. Nothing here is published.
module hide/cross-surface/go-adapter

go 1.24

require github.com/hide-protocol/hide/sdk/go v0.0.0

replace github.com/hide-protocol/hide/sdk/go => ../../../../sdk/go
