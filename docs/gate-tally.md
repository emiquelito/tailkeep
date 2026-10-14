# Gate tally

This file records, per rule, every time a gate rejected a deliverable and
what it caught. It is a measurement log, not a design document.

Each entry should say where to see the result, so a reader can check it
instead of taking it on trust: a test file, a script's output, or a
commit that carries the fix. Run `agent-delivery-gates tally --check` to
find an entry that is missing one, or that names a rule id that does not
exist.

| # | Date | Rule | Where to see it | What it caught |
|---|------|------|------|----------------|
| 1 | 2026-10-13 | coverage-as-gap-finder | `internal/classify/ollama_test.go` (TestResponseSizeBoundary) | Mutation run on the classifier client: changing the reply size check from `>` to `>=` survived, so no test pinned the boundary. Added a test with replies of exactly the limit and one byte over. |
| 2 | 2026-10-13 | coverage-as-gap-finder | `internal/classify/ollama_test.go` (TestFakeNoDelayIgnoresContext) | Mutation run on the test fake: changing the delay check from `> 0` to `>= 0` survived, so no test showed that a fake without a delay answers at once even when the context has ended. Added that test. |

## Mutation run notes: audit, llmproxy, web

`adg mutate` on `internal/audit`, `internal/llmproxy` and `internal/web`
(non-test files, `go test ./...`): 67 planned and attempted, 60 killed, 0
survived, 7 without a verdict. The 7 are six string `+` to `-` mutants that
cannot compile (audit.go 128 and 133, llmproxy.go 128 twice, web.go 103
twice) and web.go 85, `&&` to `||`, which `go vet` rejects as a comparison
that is always true. That mutant is the same as refusing every POST; the
hand mutants `site != "same-origin"` (absent header refused) and
`site == "never-sent"` (check removed) were both killed.

Hand mutants, in a scratch copy: 69 applied, 67 killed. The two survivors
have a written reason:

- audit limit: removing `min(limit, MaxLimit)` in `Log.Entries`. The ring
  holds `RingSize` (500) entries and `MaxLimit` is also 500, so the ring
  already caps every result. The line stays so raising the ring size cannot
  raise the page limit by accident. Trigger: `RingSize` and `MaxLimit` are
  set apart.
- web scan: loading the policy with `HookPath` instead of `WebPath`. The
  paths differ only in the `model_check` default, and the scan skips the
  model check at this point, so no output differs. Trigger: the classifier
  is wired in (a later change) and the test for `model_check` on the web
  path is added there.
