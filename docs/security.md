# Security model

What protects what, the tests that prove it, and what is out of scope. [Back to the README](../README.md)

## Protections

- **Protection in two places on the hook.** First, the tailnet policy opens port 8443 on `tag:tailkeep` to `tag:aperture` alone, so no other device can open a connection to it. Second, the handler looks up the caller with WhoIs and refuses anyone without the `hook` capability, whatever the network let through. A person is stopped by either one on its own, and a mistake in one is covered by the other. The grant is about reachability; the capability is about permission. The model node is built the same way: port 443 on `tag:tailkeep-llm`, then the `llm` capability. (See checks 1, 9 and 10 below.)
- **No API keys.** Users and Aperture do not present a key. The only secrets are the two tagged auth keys, which are read from environment variables on the first start of each node and never logged.
- **Deny by default.** No capability means `block`. An unknown caller, a lookup error or a malformed capability on the hook or model node is a `403`. On the web app a caller who cannot be identified gets `403` on scans and answers, and a caller with no grant gets `403` on answers and a detector-only scan. (See checks 1 and 9 below.)
- **Strictest wins.** When grants overlap, protection fields take the strictest value and permissions add up, so a new grant cannot weaken protection by accident. (See check 3 below.)
- **Unknown stays unknown.** A model failure is recorded as `unknown`, and the policy field `on_unknown` decides. (See check 2 below.)
- **The model node serves inference only.** It forwards `POST /v1/chat/completions`, `GET /v1/models` and `POST /api/chat`. Every other path, including Ollama's pull, delete, create, copy and push, is `404`, so a granted caller can run the model but never change which models exist. The caller check runs first, so a caller without the `llm` capability learns nothing about which paths exist. Ollama listens on `127.0.0.1` only. (See check 5 below.)
- **TLS only.** The guard has no plain-HTTP listener on any port.
- **Secrets never logged.** An audit entry has no field that can hold scanned text, and a final pass redacts anything secret-like in strings that come from outside, such as device names. Previews are four characters at most. The audit file (`audit.jsonl` in the state directory) is created with mode 0600 in a 0700 folder, and an existing file with broader permissions is tightened to 0600 on Unix. Windows does not enforce Unix file modes, so there the state directory's own access rules apply. The audit page shows only entries since the process started; the file is never read back, so restarting `serve` gives a clean page. (See check 4 below for the redaction.)
- **Why a device cannot claim a tag it was not given.** Tags come from the control plane: from `tagOwners` in the policy file and from the tagged auth key a device joins with. tailkeep takes tags from the WhoIs node and never from the user profile, which is a placeholder for tagged devices.
- **Cross-site protection** on the web app: the `Host` and `Sec-Fetch-Site`/`Origin` checks described in [Policy reference](policy.md#policy-reference), a strict Content-Security-Policy on the pages, and no CORS headers. (See check 6 below.)

## Induced-failure checks

The checks below are proven by removing each protection and watching the named test fail, using agent-delivery-gates `induce`.

| # | Claim | Test | Check it removes |
|---|---|---|---|
| 1 | Only callers with the `llm` capability reach the model node; everyone else gets `403` | [TestOnlyGrantedCallersReachTheModelNode](../internal/llmproxy/llmproxy_test.go) | the caller check, so every caller is let in |
| 2 | A failed model check is `unknown`, never `clean` or `sensitive` | [TestFailuresAreUnknown](../internal/classify/ollama_test.go), [TestTimeoutIsUnknown](../internal/classify/ollama_test.go), [TestTransportErrorIsUnknown](../internal/classify/ollama_test.go) | the `unknown` result, so every failure is reported as `clean` |
| 3 | With several grants the strictest protection wins | [TestStrictestGrantWins](../internal/policy/policy_test.go) | the strictness order, reversed so the loosest action wins |
| 4 | Secret-like strings from outside, such as device names, are redacted before they reach the audit log | [TestScrubRemovesSecretShapedStrings](../internal/audit/audit_test.go) | the redaction of secret-like strings in audit entries |
| 5 | A granted caller can run a model but not manage it (pull, delete, create, copy, push, tags) | [TestManagementEndpointsAreRefused](../internal/llmproxy/llmproxy_test.go) | the path allowlist, so Ollama's management endpoints pass |
| 6 | A cross-site `POST` to the web app is refused with `403` | [TestCrossSitePostIsRefused](../internal/web/web_test.go) | the `Sec-Fetch-Site` and `Origin` checks |
| 7 | The hygiene check finds banned words, credential-looking values, Tailscale addresses and names, and other emails | [TestPlantedFileTripsEveryRule](../internal/hygiene/hygiene_test.go) | the rule list, emptied so nothing is found |
| 8 | Text whose decision is `block` reaches no model | [TestBlockedAnswerReachesNoModel](../internal/web/answer_test.go) | the stop on a `block` decision before the model is called |
| 9 | Only a caller with the `hook` capability gets an answer from the hook | [TestOnlyApertureCanCallTheHook](../internal/hook/hook_test.go) | the hook caller check, so every caller is let in |
| 10 | The hook path does not exist on the web port | [TestHookListenerServesOnlyTheHookRoute](../internal/server/serve_test.go) | the separation of the ports, so the hook route is also served on the web port |
| 11 | A fake AWS key never gets `allow` or `modify` for a `block` or `reroute` user on a cloud provider | [TestFakeKeyNeverReachesACloudModel](../internal/hook/hook_test.go) | the detectors, which then find nothing |
| 12 | A secret only in a tool-result message is caught | [TestToolResultSecretIsCaught](../internal/hook/hook_test.go) | the scan of the whole request body, leaving only `user_message` scanned |

Claims with no induced-failure check: "No API keys", "TLS only" and "Why a device cannot claim a tag it was not given".

## Out of scope

- Funnel or any public access.
- Bring-your-own-key for users.
- A general chat interface. The web app checks text and can ask the local model about it, nothing more.
- Response-side scanning, MCP tool calls and connector traffic.
- Secrets inside images or files, or only in an encoded form.
- A compromised node or an administrator of the tailnet, who can change the policy.
- Rate limiting and protection against a granted caller who sends many requests.
