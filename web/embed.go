// Package webassets holds the web app's pages. The files live in the
// top-level web directory, and go:embed cannot reach up from internal/web, so
// this small package embeds them and internal/web imports it.
package webassets

import "embed"

// FS holds index.html and audit.html.
//
//go:embed index.html audit.html
var FS embed.FS
