// Command tailkeep keeps sensitive prompts on your tailnet. Subcommands:
// serve (the default), doctor and check.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/emiquelito/tailkeep/internal/classify"
	"github.com/emiquelito/tailkeep/internal/detect"
	"github.com/emiquelito/tailkeep/internal/policy"
	"github.com/emiquelito/tailkeep/internal/server"
)

const maxInput = 10 << 20

const (
	defaultOllamaURL = "http://127.0.0.1:11434"
	defaultModel     = "granite4.1:3b"
)

// These are variables only so tests can replace the parts that need a
// tailnet.
var (
	runServe   = server.Run
	startNodes = server.StartNodes
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, in io.Reader, out, errw io.Writer) int {
	if len(args) == 0 {
		args = []string{"serve"}
	}
	switch args[0] {
	case "check":
		return check(args[1:], in, out, errw)
	case "serve":
		return serve(args[1:], out, errw)
	case "doctor":
		return doctor(args[1:], out, errw)
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

// commonFlags defines the flags serve and doctor share. The Ollama address
// defaults to the OLLAMA_URL environment variable when it is set.
func commonFlags(name string, errw io.Writer) (fs *flag.FlagSet, stateDir, ollama *string) {
	fs = flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(errw)
	stateDir = fs.String("state-dir", "", "where node state is kept (default: <user config dir>/tailkeep)")
	ollama = fs.String("ollama-url", envOr("OLLAMA_URL", defaultOllamaURL), "address of Ollama (default: $OLLAMA_URL, else "+defaultOllamaURL+")")
	return fs, stateDir, ollama
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// serve runs both nodes until SIGINT or SIGTERM.
func serve(args []string, out, errw io.Writer) int {
	fs, stateDir, ollama := commonFlags("serve", errw)
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(errw, nil))
	if err := runServe(ctx, server.Config{StateDir: *stateDir, OllamaURL: *ollama}, out, log, startNodes); err != nil {
		fmt.Fprintln(errw, "tailkeep serve:", err)
		return 1
	}
	return 0
}

// doctor checks Ollama and both nodes, and stops at the first failure.
func doctor(args []string, out, errw io.Writer) int {
	fs, stateDir, ollama := commonFlags("doctor", errw)
	model := fs.String("model", defaultModel, "model the local checks use")
	pull := fs.Bool("pull-model", false, "pull the model through Ollama on this machine if it is missing")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	paths, err := server.StatePaths(*stateDir)
	var ollamaURL *url.URL
	if err == nil {
		ollamaURL, err = server.ParseOllamaURL(*ollama)
	}
	if err != nil {
		fmt.Fprintln(errw, "tailkeep doctor:", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d := &server.Doctor{
		Out: out,
		Log: slog.New(slog.NewTextHandler(errw, nil)),
		Ollama: &server.Ollama{
			URL: ollamaURL, Model: *model, PullModel: *pull,
			GOOS: runtime.GOOS, Client: server.NewOllamaClient(), Out: out,
		},
		Paths: paths,
		Start: startNodes,
	}
	return d.Run(ctx)
}
