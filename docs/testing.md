# Testing

[Back to the README](../README.md)

```sh
npm ci            # once: installs the development tooling (see below)
go vet ./...
gofmt -l .        # prints nothing when files are formatted
go test ./...
```

- **Unit tests** run offline. They use fakes for identity and the model client, and no unit test is allowed to start a real tailnet node (a test fails if a test file refers to the tsnet package or the real node starter).
- **Integration tests** run against a live tailnet. They start no node of their own: they use the network connection of the device they run on, so the device is the identity under test (run them on the alice device, the bob device and the `tag:ci-agent` device). Each test skips when its variables are unset. The variables are listed in the header of `integration/env_test.go`: `TAILKEEP_IT_GUARD`, `TAILKEEP_IT_EXPECT` (`alice`, `bob` or `ci-agent`), `TAILKEEP_IT_LLM`, `TAILKEEP_IT_HOOK_PORT`, and for the Aperture tests `TAILKEEP_IT_APERTURE`, `TAILKEEP_IT_CLOUD_MODEL` and `TAILKEEP_IT_LOCAL_MODEL`, plus a few optional ones (login check, latency count, the two policy-change tests behind `TAILKEEP_IT_PROPAGATION`).
  ```sh
  go test -tags integration ./integration/
  ```
  They are not part of `go test ./...`. The classifier check is a separate integration test in `internal/classify`; it needs `TAILKEEP_CLASSIFY_URL` to point at an Ollama address (see [Why this model](detectors-and-model.md#why-this-model)).
- **Public-repository check.** `go test -tags hygiene ./...` scans every tracked file for banned words, credential-looking strings, Tailscale addresses, real `.ts.net` names, emails other than `@example.com`, and a private list of values that is never written in the repository. That list comes from the environment variable `TAILKEEP_HYGIENE_PRIVATE`; without it, that one rule is skipped and a notice says so. The list must contain the owner name exactly as the `LICENSE` copyright line spells it, or that line is reported. Findings print the file, line and rule, never the matched text. If a file's own name is the problem, it prints `<tracked file #N>`; resolve it with `git ls-files | sed -n Np`, replacing `N`. The check cannot see commit metadata, git history, images and video, binary or UTF-16 files, look-alike characters, or files that are not tracked or staged yet.
- **Commit checks.** Commits run the agent-delivery-gates checks (vet, gofmt, hygiene, tests and more; see [gate-tally.md](gate-tally.md)). A fresh clone runs no hook until you set `core.hooksPath` and run `npm ci`:
  ```sh
  git config core.hooksPath .githooks
  ```
  The same steps run in CI.

## The `check` command

`check` reads text from standard input, runs the detectors and prints the decision for a policy action (`--action`, default `block`). It does not use the network and never prints the text it scanned. The key below is the public AWS documentation example, assembled in the shell so this file holds no key-like string:

```sh
printf 'aws_access_key_id = %s%s\n' AKIA IOSFODNN7EXAMPLE | go run ./cmd/tailkeep check --action block
```

```
findings: 1
  aws_access_key [20,40) AKIA…
decision: block (found aws_access_key)
```

The numbers are byte offsets. The preview shows at most four characters. With `--action redact` the decision line reads `decision: redact (found aws_access_key)`. Text with nothing in it gives `decision: allow (nothing found)`. `check` skips the local model, so `--action reroute` and `--action block` differ only in the action name.
