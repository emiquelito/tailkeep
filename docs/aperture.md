# Using it with Aperture

[Back to the README](../README.md)

This part is optional. The web app, the audit page and the model node work without Aperture.

Aperture can call tailkeep's hook before it forwards a request. The full setup (providers, the hook entry, grants) is in [examples/aperture.example.md](../examples/aperture.example.md), and the tailnet side is in [examples/policy.example.hujson](../examples/policy.example.hujson). Aperture's own model and hook grants go in Aperture's configuration, as shown in the first file, not in the tailnet policy file.

How the hook behaves:

- **Endpoint.** `POST /aperture/pre-request` on its own port, 8443 by default (`--hook-port`), served by a separate listener that has only this route. On port 443 a JSON `POST` to that path gets `404` (a request that fails the Host or cross-site checks gets `403` first).
- **Callers.** Only a caller holding the `hook` capability gets an answer; anyone else gets `403` naming the caller, and the refusal is audited. Aperture's `apikey` is not needed: tailkeep ignores whatever value is sent and identifies Aperture through WhoIs.
- **End user.** The hook payload carries the end user's `stable_node_id` and `login_name`. tailkeep looks the device up by that ID and reads the policy that device holds toward the guard. It checks that the device's login (or, for a tagged device, its tags sorted and joined with commas, which is what Aperture's documentation says it sends; confirmed live: a tagged device's hook audit entry names its tag as the end user) matches `login_name`. A mismatch is blocked and audited as an integrity error.
- **Visibility.** The guard can only look up devices it can see, which depends on network grants. Every person whose Aperture traffic goes through the hook needs at least the grant from their devices to `tag:tailkeep:443`. A device the guard cannot see is blocked with the reason "device not visible to tailkeep".
- **What is scanned.** The whole `request_body`, not only the last message: every string value in the JSON is scanned, so a secret in a tool-result message (for example a `.env` file an agent read) is caught even though nobody typed it. This works the same for OpenAI chat, OpenAI Responses and Anthropic message bodies. Numbers are written back exactly as received. The `user_message` field is scanned too. A `redact` action whose only finding is in `user_message` becomes `block`, because only `request_body` is rewritten.
- **Answers.** `allow`; `modify`, with the full body and each finding replaced by `[REDACTED:<detector>]` (only for `redact`); or `block` with `status_code` 451 and a message that names the detector or category, never the secret. Hook answers are sent with HTTP status 200.
- **Measured live.** Through Aperture, 20 requests per series. A blocked request had a median of 312 ms and a p95 of 315 ms. A clean request (includes the cloud model's answer) had a median of 1.48 s and a p95 of 1.96 s. The hook handler took 0 to 1 ms, far under the 2 second timeout, so nearly all of the 312 ms is the trip through Aperture.
- **Also confirmed live.** Aperture returns HTTP 451 with `error.type` `guardrail_blocked` to the client. A `reroute` user gets the "Send this request to <local model> instead." message and a `block` user gets the block without it. A key that appears only in an earlier tool-result message is blocked. The hook port is closed at the network layer, and tailkeep answers `403` when the network allows the connection. With grants, the `reroute` user gets local-model answers, the `block` user gets `403` on answers, and the model node refuses callers without `llm`.
- **Request size.** At most 10 MB. A larger request gets `413`, audited.
- **Requests already going to the local model.** This is decided by the target provider in the hook payload, matched to `--local-provider` (default `local`), not by model name. That flag must name the self-hosted provider, the one pointing at tailkeep-llm; naming a cloud provider would exempt it from redact and reroute. For those requests `allow`, `redact` and `reroute` answer `allow` unchanged, since the text stays on the tailnet. `block` still blocks.

**Why `reroute` blocks here.** Aperture chooses the provider for a request before it runs any hook, so a hook cannot move a request to another provider. When the caller's action is `reroute` and the request targets a cloud provider, the hook answers `block` with 451 and a message such as "Sensitive content found (aws_access_key). Send this request to granite4.1:3b instead." (using the configured model name). The person sends the request again with the local model, Aperture routes it to the local provider, the hook sees the target is local, and the request is allowed.

**`fail_closed` is required.** Set `fail_policy: fail_closed` on the hook in Aperture. Some refusals are not HTTP success: `403` for a caller that is not Aperture and `413` for an oversize body. Under `fail_open`, Aperture is documented to let a request through when its hook fails (not tested live; only `fail_closed` was observed), so an oversize body would never be scanned and a mis-granted Aperture would pass every request. Most other blocks are sent as HTTP 200 with `status_code` 451, so they hold under either policy.

These cases also block: a device the guard cannot see, a failed lookup, a login mismatch, an end user whose capability is malformed, a body that is not JSON, and a body in which an object repeats a key. The repeated key case is blocked because a provider might read the first copy while tailkeep read the last, hiding a secret in the copy it never saw.

Known limits on this path:

- Only requests are scanned. Aperture guardrails do not see responses, MCP tool calls or connector traffic, and tailkeep does not offer response scanning.
- Strings are scanned as written. A secret that exists only base64-encoded is not found.
- Large binary payloads are skipped: a `data:` URL with a base64 payload, and the `data` of a base64 source block (image or document blocks), when the payload is 1 KB or more and decodes to non-text bytes. A secret inside an image or an uploaded file is not detected.
- JSON object keys are not scanned and not redacted. A secret placed in a key is not found.
- The hook uses the model check only if a grant sets `model_check` to `true`. A model call through the model node takes a median of about 1.1 s and about 7 s on the first call, so with a short hook timeout leave it off here.
- A `redact` rewrite changes earlier messages in the body, which can reduce the provider's prompt-cache hits (per Aperture's documentation; not measured here).
- Devices outside the tailnet that reach Aperture through a bridge are not supported, because the stable ID would belong to the bridge (a design limit; not tested).
