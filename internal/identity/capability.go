// Package identity holds tailkeep's caller identity types.
package identity

import "tailscale.com/tailcfg/peercap"

// CapName is the tailnet policy app capability that carries tailkeep policy.
const CapName peercap.Cap = "github.com/emiquelito/tailkeep"
