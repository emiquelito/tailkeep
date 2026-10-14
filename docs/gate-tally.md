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
| 3 | 2026-10-13 | coverage-as-gap-finder | `internal/hygiene/hygiene_test.go` (TestParseIPv4) | Mutation run on the hygiene check: the octet validation in the address parser survived three mutants (an "or" turned into "and" twice, and the not-an-address result turned into an address), so no test pinned how a bad octet is rejected. Replaced the length and range checks with one unsigned 8-bit parse and added a direct test of the parser. |
| 4 | 2026-10-13 | coverage-as-gap-finder | `internal/hygiene/hygiene_test.go` (TestBinaryAndMediaFilesAreSkipped) | Mutation run on the hygiene check: changing the binary-file test from `>= 0` to `> 0` survived, so no test showed that a file whose first byte is a NUL byte counts as binary. Added that file to the test. |
| 5 | 2026-10-13 | coverage-as-gap-finder | `internal/hygiene/hygiene_test.go` (TestHints) | Mutation run on the hygiene check: setting the "hint already printed" flag to false survived, so no test showed that two findings on the LICENSE file give one hint line, not two. Added a second finding to the test. |
| 6 | 2026-10-13 | coverage-as-gap-finder | `internal/server/serve_test.go` (TestServeWiresEachMuxToItsOwnNode) | Hand mutant on the server wiring: building the web app's resolver from the model node's local client survived, because both fakes described the same user. The two fakes now describe different users and the page must show the guard's. |
| 7 | 2026-10-13 | coverage-as-gap-finder | `internal/server/serve_test.go` (TestServersGetTheirOwnLimits) | Hand mutants: giving the model node the web limits, the web app the model node limits, or a ten-hour header timeout all survived, because the limits were only checked to be above zero. The test now pins every value for both servers. |
| 8 | 2026-10-13 | coverage-as-gap-finder | `internal/server/ollama_test.go` (TestIsLoopback) | Hand mutant: treating private addresses as this machine survived, so `--pull-model` could have been sent to a LAN host. Added private IPv4 ranges, the shared carrier range and a unique-local IPv6 case. |
| 9 | 2026-10-13 | coverage-as-gap-finder | `internal/server/doctor_test.go` (TestDoctorPasses, TestDoctorWhoIsFailures) | adg mutate found 17 survivors in the doctor's real tailnet code, and hand mutants skipping the own-address check and asking for the wrong model node name survived. That code sat behind an interface only a real tailnet used. The interface is gone and the same code now runs against fake nodes. |
| 10 | 2026-10-13 | coverage-as-gap-finder | `internal/server/ollama_test.go` (TestOllamaErrorStatusIsNotOllama) | Hand mutant: accepting any HTTP status as "Ollama is reachable" survived. Added a test with a 500 answer. |
| 11 | 2026-10-13 | coverage-as-gap-finder | `internal/server/ollama_test.go` (TestPullModelStreamsProgress, TestAnswersReportsTheTime), `internal/server/serve_test.go` (TestStopReportsARequestThatOutlastsTheWait) | adg mutate after the doctor was simplified: dropping the JSON Content-Type header and flipping the shutdown error check both survived. The fake Ollama now records the header, and a request held open past the wait shows stop returns the deadline error. |
| 12 | 2026-10-13 | coverage-as-gap-finder | `internal/web/answer_test.go` (TestNewRequiresClassifierAndAnswerer, TestZeroAnswerCapMeansTheDefault) | adg mutate on the classifier wiring and the answers route: the constructor check for a missing classifier or answerer accepted a config missing only one of them, and a zero answer cap ("use the default") could become "send nothing" without a test noticing. Both now have tests. |

## Mutation run notes: audit, llmproxy, web

`adg mutate` on `internal/audit`, `internal/llmproxy` and `internal/web`
(non-test files, `go test ./...`): 67 planned and attempted, 60 killed, 0
survived, 7 without a verdict. The 7 are six string `+` to `-` mutants that
cannot compile (audit.go 128 and 133, llmproxy.go 128 twice, web.go 103
twice) and web.go 85, `&&` to `||`, which `go vet` rejects as a comparison
that is always true. That mutant is the same as refusing every POST; the
hand mutants `site != "same-origin"` (absent header refused) and
`site == "never-sent"` (check removed) were both killed.

Hand mutants, applied to a temporary copy: 69 applied, 67 killed. The two survivors
have a written reason:

- audit limit: removing `min(limit, MaxLimit)` in `Log.Entries`. The ring
  holds `RingSize` (500) entries and `MaxLimit` is also 500, so the ring
  already caps every result. The line stays so raising the ring size cannot
  raise the page limit by accident. Trigger: `RingSize` and `MaxLimit` are
  set apart.
- web scan: loading the policy with `HookPath` instead of `WebPath`. It
  survived while the scan skipped the model check. Closed once the web path
  asked the classifier: `TestWebPathModelCheckDefaultIsOn` fails on that mutant, because a
  caller with a grant that does not mention `model_check` must be classified.

## Mutation run notes: server, doctor, serve

`adg mutate` on the server files (not `tsnet.go`, which builds the real node
type; a mutant there once let a test start a real node, so it is no longer
mutated and tests are barred from reaching it, see
`TestNoTestStartsARealTailnetNode`). Survivors left, each with a reason (the `Shutdown` error branch of `running.stop`
was one until `TestStopReportsARequestThatOutlastsTheWait` pinned it):

- `upTimeout` (two minutes) and the node close order: values and ordering
  with no observable effect offline; both live only around a real node.
  Trigger: a real tailnet shows a node that needs longer than two minutes,
  or a close-order problem.
- `tsnet.go` (`StartNode`, `StartNodes`, `Local`): the thin calls to the real
  library, proven only on a real tailnet. The first-start key rule
  (`checkKey`) and the node settings are pure and tested.

## Mutation run notes: classifier wiring and answers

`adg mutate` on `internal/web/web.go`, `internal/web/answer.go`,
`internal/server/serve.go`, `internal/server/config.go` and
`cmd/tailkeep/main.go`: 111 attempted, 82 killed, 2 survived (both killed
after the two tests in row 12), 16 timeouts and 11 that do not build. The
timeouts are `err != nil` flipped to `== nil` in the serve wiring and
config code, which hangs a test: they end the run as failed, not as passed.
The 11 build failures are string `+` to `-` mutants. 56 hand mutants in a
temporary copy (block gate, cap and note, skip rule, unknown handling, write
deadline, model reason leaks, audit calls, client and host wiring, flag):
all killed.
