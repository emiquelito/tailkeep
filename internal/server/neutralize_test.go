//go:build adg_neutralize

package server

import (
	"net/http"

	"github.com/emiquelito/tailkeep/internal/hook"
)

// Test builds with the adg_neutralize tag register the hook route on the web
// port as well, so the induced-failure spec can show the test fails when the
// hook path exists there. No production file changes; the default build does
// not include this file.
func init() {
	webPortHandler = func(web, hookMux http.Handler) http.Handler {
		mux := http.NewServeMux()
		mux.Handle(hook.Path, hookMux)
		mux.Handle("/", web)
		return mux
	}
}
