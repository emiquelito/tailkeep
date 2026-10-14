# Policy reference

Grant fields, how grants combine, and the web app's endpoints and limits. [Back to the README](../README.md)

tailkeep reads one app capability, `github.com/emiquelito/tailkeep`, from the grants that apply to the caller toward the node it calls. Each grant carries one JSON object. Every field is optional:

```json
{ "action": "reroute", "on_unknown": "block", "model_check": true, "view": "all", "hook": false, "llm": false }
```

| Field | Values | Default | Meaning |
|---|---|---|---|
| `action` | `allow`, `redact`, `reroute`, `block` | `block` | what to do when content is found sensitive |
| `on_unknown` | `allow`, `block` | `block` | what to do when the model check cannot decide (see [Detectors and the local model](detectors-and-model.md)) |
| `model_check` | `true`, `false` | `true` on the web app, `false` on the hook path | also ask the local model to classify the text. The detectors always run |
| `view` | `self`, `all` | `self` | audit scope: own entries only, or all entries |
| `hook` | `true`, `false` | `false` | this caller may call the Aperture hook (meant for `tag:aperture`) |
| `llm` | `true`, `false` | `false` | this caller may use the model node (meant for `tag:aperture` and `tag:tailkeep`) |

An example grant for one person, in the tailnet policy file:

```json
{
  "src": ["alice@example.com"],
  "dst": ["tag:tailkeep"],
  "app": { "github.com/emiquelito/tailkeep": [ { "action": "reroute", "view": "all" } ] }
}
```

The destination is the node the caller talks to, because WhoIs returns the capabilities a caller holds toward that node. People need the grant toward `tag:tailkeep`, including for the hook path, where the guard looks up the person's device and reads their policy. Aperture needs `hook` toward `tag:tailkeep` and `llm` toward `tag:tailkeep-llm`. The guard needs `llm` toward `tag:tailkeep-llm`.

A grant that leaves a field out has no opinion on it. A grant that only sets `hook` adds the hook permission without changing the protection fields.

**When several grants apply**, the fields combine in two ways:

- Protection fields take the strictest value. For `action` the order is `block`, then `reroute`, then `redact`, then `allow`. For `on_unknown`, `block` beats `allow`. `model_check` is `true` if any grant says `true`. If no grant sets `action` or `on_unknown`, the value is `block`. If no grant sets `model_check`, the per-path default applies.
- Permission fields add up, the way Tailscale grants normally combine. `view` is `all` if any grant says `all`. `hook` and `llm` are true if any grant says true.

The reason: adding a grant can add permissions, but it can never weaken protection by accident.

**No capability.** A caller with no tailkeep capability gets `action: block`, `on_unknown: block`, `view: self`, no `hook`, no `llm`. On the web app such a device cannot use `POST /api/answers` (it gets `403`, reason "no tailkeep grant for this device", and is audited), and its `POST /api/scans` runs the detectors only: the local classifier is skipped and the class is `skipped`, so no model reads its text. Any grant, even one that only sets `hook` or `view`, lifts this. A malformed capability is refused as described next.

**Malformed capability.** If any grant is not valid JSON, has a wrong type, has a value tailkeep does not accept, or has a field tailkeep does not know, the whole capability is rejected and the caller gets the same policy as having none. The web app shows "malformed capability (deny)", `POST /api/answers` and the model node answer `403`, and the cause is logged. An unknown field denies the capability on purpose, so a typo such as `acton` cannot become "no opinion". The cost is that adding a field in a newer version of tailkeep denies callers on an older binary until it is upgraded.

A caller with no tailkeep capability can still reach the web app if the network grants let them connect, but they get no answers (`403`) and only a detector-only scan. Use network grants to control who can reach `tag:tailkeep:443`.

Grants are read from WhoIs on every request. tailkeep keeps no policy cache and needs no restart when a grant changes. In one quick live check a policy file change reached tailkeep in about 1 to 2 seconds (approximate, one check, not a benchmark).

## Web app endpoints

tailkeep's own JSON API uses plural nouns, with the HTTP method as the action. Two paths keep other names on purpose: `POST /aperture/pre-request` matches Aperture's `pre_request` event name, and the model node's paths are Ollama's own (`/api/chat`, `/v1/chat/completions`), which tailkeep forwards and cannot rename.

| Endpoint | Does | Success |
|---|---|---|
| `GET /`, `GET /audit` | the app page and the audit page | `200` |
| `POST /api/scans` | body `{"text": "..."}`; returns the action, reason, findings (detector and a short preview), classification and, when there are spans, a redacted preview. The text is not stored | `201` |
| `POST /api/answers` | body `{"text": "...", "question": "..."}`; the local model answers about the text. A device with no tailkeep grant gets `403`. A `block` decision returns `403` before the answering model is called (the classifier may already have read the first 2,000 characters, see the [note on block](detectors-and-model.md#a-note-on-block)) | `201` |
| `GET /api/audit-entries` | entries newest first, filtered by the caller's `view`; `?limit=` defaults to 50, maximum 500. The page polls it every 2 seconds | `200` |

Errors are always `{"error": "<code>", "reason": "<text>"}` with the matching status: `400`, `403`, `404`, `413`, `500` if a page cannot be built, or `502` when the local model did not answer.

Limits: scan and answer bodies are at most 256 KB (`413` above that). A question is at most 1,000 characters. The answer is at most 512 tokens. There is no rate limit: one answer can hold a handler for up to about 140 seconds (20 s for the classifier plus up to 120 s for the model, inside a 150 s deadline), so use network grants to decide who can reach the web app.

Every request to the web app must pass two checks, otherwise `403`:

- The `Host` header must equal the guard's own bare MagicDNS name (`tailkeep.<tailnet>.ts.net`). Reaching the app by IP address, by a short name or through a proxy that rewrites `Host` fails. This blocks DNS rebinding.
- For `POST`: `Sec-Fetch-Site` must be `same-origin` or absent (so `curl` works), `Origin` when present must be the guard's own HTTPS origin, and the body must be `Content-Type: application/json`. This blocks a page in your browser from making requests as you. No CORS header is ever sent.

For example, with `curl` from a device that holds a grant:

```sh
curl -s -X POST https://tailkeep.<tailnet>.ts.net/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"text": "aws_access_key_id = <FAKE_AWS_KEY>"}'
```

Where the [README](../README.md) shows a key, `<FAKE_AWS_KEY>` stands for a key you build yourself at run time. Do not paste a real key.

## Command-line flags and first start

`serve` runs when `tailkeep` is started with no arguments at all. Flags given without a subcommand print the usage text and exit with status 2. Flags:

| Flag | Default | Used by |
|---|---|---|
| `--state-dir` | `<user config dir>/tailkeep` | serve, doctor |
| `--ollama-url` | `$OLLAMA_URL`, else `http://127.0.0.1:11434` | serve, doctor |
| `--model` | `granite4.1:3b` | serve, doctor |
| `--hook-port` | `8443` | serve |
| `--local-provider` | `local` | serve |
| `--pull-model` | off | doctor |

Do not run `doctor` while `serve` is running on the same state directory. Both use the same node state, and `doctor` starts its own copies of the nodes.

On the first start the certificate fetch took about 31 to 35 seconds per node in a live run. A restart reuses the stored certificates and took about 0.1 to 0.3 seconds. `serve` fetches both before it listens, and `doctor` fetches them too, so run `doctor` once before a demo. In the live run `doctor` passed all its checks, and `serve` started right after it on the same state directory.

Ollama can run on a CPU, but that is untested here, and it will be slower. `doctor` prints the measured time of one small prompt.
