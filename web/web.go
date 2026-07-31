// Package web embeds the panel's front-end assets into the binary.
//
// Embedding rather than serving from disk means the deployed artifact is a
// single file: there is no asset directory to forget to copy, and no runtime
// path that can differ between local and production.
package web

import "embed"

// Assets holds the panel UI and the server-rendered subscription template.
//
//go:embed assets
var Assets embed.FS
