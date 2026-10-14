// Command tailkeep keeps sensitive prompts on your tailnet. Only the check
// subcommand exists so far; serve and doctor are placeholders.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/emiquelito/tailkeep/internal/classify"
	"github.com/emiquelito/tailkeep/internal/detect"
	"github.com/emiquelito/tailkeep/internal/policy"
)

const maxInput = 10 << 20

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, in io.Reader, out, errw io.Writer) int {
	if len(args) == 0 {
		args = []string{"serve"}
	}
	switch args[0] {
	case "check":
		return check(args[1:], in, out, errw)
	case "serve", "doctor":
		fmt.Fprintf(errw, "tailkeep %s: not implemented yet\n", args[0])
	default:
		fmt.Fprintln(errw, "usage: tailkeep [serve|doctor|check]")
	}
	return 2
}

// check scans stdin offline and prints findings (previews only) and the
// decision. Classification is skipped. It never prints the scanned text.
func check(args []string, in io.Reader, out, errw io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(errw)
	action := fs.String("action", "block", "policy action: allow|redact|reroute|block")
	if fs.Parse(args) != nil {
		return 2
	}
	p := policy.Policy{Action: policy.Action(*action), OnUnknown: policy.Block, View: policy.Self}
	if err := p.Validate(); err != nil {
		fmt.Fprintln(errw, "tailkeep check:", err)
		return 2
	}
	text, err := io.ReadAll(io.LimitReader(in, maxInput+1))
	if err != nil || len(text) > maxInput {
		fmt.Fprintln(errw, "tailkeep check: cannot read input (read error or over 10 MB)")
		return 2
	}
	found := detect.Detect(string(text))
	dec := policy.Decide(p, found, classify.Result{Label: classify.Skipped})
	fmt.Fprintf(out, "findings: %d\n", len(found))
	for _, f := range found {
		fmt.Fprintf(out, "  %s [%d,%d) %s\n", f.Detector, f.Start, f.End, f.Preview)
	}
	fmt.Fprintf(out, "decision: %s (%s)\n", dec.Action, dec.Reason)
	return 0
}
