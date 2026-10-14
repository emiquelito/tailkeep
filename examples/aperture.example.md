# Using tailkeep with Aperture

This guide connects an Aperture instance to tailkeep. It is optional: the
web app, the audit page and the model node work without Aperture. Every name
below is a placeholder. Replace `<tailnet>`, the model names and the logins
with your own. Aperture's own documentation is the reference for its
configuration format, and the examples below use it.

## What you get

Aperture picks the provider for a request first, then calls tailkeep's hook
with the request. The hook looks at the whole request body, including tool
results, and answers allow, modify (redact) or block.

| Policy action | Request to a cloud provider | Request to the local provider |
|---|---|---|
| `allow` | passes unchanged | passes |
| `redact` | the body is sent with each finding replaced by `[REDACTED:<detector>]` | passes unchanged |
| `reroute` | blocked with the message "Sensitive content found (...). Send this request to `<local model>` instead." | passes unchanged |
| `block` | blocked | blocked |

Reroute is block-with-guidance on this path. Aperture chooses the provider
before any hook runs, so a hook cannot move a request to another provider.
The person sends the request again with the local model name; Aperture routes
it to the local provider, the hook sees that the target provider is the local
one and allows it. The decision about the local provider comes from the
provider name in the hook payload, not from the model name.

## 1. Providers

Add two providers to Aperture's `providers` section.

```jsonc
{
  "providers": {
    // The local model, served by tailkeep-llm in front of Ollama. Do not add
    // /v1 to baseurl: Aperture appends the request path itself.
    "local": {
      "baseurl": "https://tailkeep-llm.<tailnet>.ts.net",
      "models": ["granite4.1:3b"],
      "compatibility": { "openai_chat": true }
    },

    // A cloud provider that uses your own key, stored in Aperture. Bringing
    // your own keys depends on your plan; check Aperture's documentation.
    "openai": {
      "baseurl": "https://api.openai.com",
      "apikey": "<your key, stored in Aperture only>",
      "models": ["<cloud-model>"],
      "compatibility": { "openai_chat": true, "openai_responses": true }
    }
  }
}
```

Keep `compatibility` at `openai_chat`: tailkeep's model node does not serve
the Anthropic messages format, so `anthropic_messages` is not supported there.

The model node only serves `POST /v1/chat/completions`, `GET /v1/models` and
`POST /api/chat`, so the local provider is for OpenAI chat completions
requests. The name `local` is the default for `tailkeep serve
--local-provider`. That flag must name the self-hosted provider, the one
pointing at tailkeep-llm. If you name the provider something else, pass that
name. Never name a cloud provider there: it would be exempt from redact and
reroute.

### One model under two providers

If the same model name is listed under two providers (for example a
passthrough provider and a key provider), Aperture needs to know which wins.
Give the provider you want a higher `preference`:

```jsonc
"openai": { "preference": 10, /* ...as above... */ }
```

Without it, requests for that model may go to the other provider. Check
Aperture's logs to see which provider answered.

## 2. The hook

Add the hook under `hooks`.

```jsonc
{
  "hooks": {
    "tailkeep": {
      "url": "https://tailkeep.<tailnet>.ts.net:8443/aperture/pre-request",
      "fail_policy": "fail_closed",
      "timeout": "2s"
    }
  }
}
```

- **Port.** 8443 is the default of `tailkeep serve --hook-port`. Only the
  Aperture device should be allowed to reach it in your tailnet policy.
- **fail_closed.** If the hook is down, slow or answers with an error,
  Aperture blocks the request. tailkeep also answers 403 to any caller that is
  not Aperture, which Aperture treats the same way. With `fail_open` a hook
  failure would let requests through unchecked, so do not use it.
- **timeout.** Aperture recommends 0.5 to 2 seconds for a pre_request hook.
  Without the model check the hook handler took 0 to 1 ms per request live; a
  blocked request took a median of 312 ms end to end through Aperture, so
  2 seconds leaves a wide margin. Do not turn on `model_check` for the hook
  path with this timeout: through the model node a local model call takes a
  median of about 1.1 s, and about 7 seconds on the first call.
- **Authentication.** tailkeep identifies Aperture from the tailnet, so no
  `apikey` is needed. If your Aperture version insists on one, any value is
  accepted and ignored.

## 3. Grants

Aperture grants decide who may use which models and which hooks receive which
fields. The hook needs `request_body` and `user_message`.

```jsonc
{
  "grants": [
    // Model access. Every block or reroute in a demo must come from tailkeep,
    // never from Aperture refusing a model, so both models are granted to
    // each identity. Reroute needs the local model granted.
    {
      "src": ["alice@example.com", "bob@example.com", "tag:ci-agent"],
      "app": {
        "tailscale.com/cap/aperture": [
          { "role": "user", "models": "openai/<cloud-model>" },
          { "role": "user", "models": "local/granite4.1:3b" }
        ]
      }
    },

    // Send every request to the hook, with the body and the last user message.
    {
      "src": ["*"],
      "app": {
        "tailscale.com/cap/aperture": [
          {
            "send_hooks": [
              {
                "name": "tailkeep",
                "events": ["pre_request"],
                "send": ["request_body", "user_message"]
              }
            ]
          }
        ]
      }
    }
  ]
}
```

Notes:

- Model patterns are `provider/model`. A pattern must name a provider that
  is declared above.
- These grants belong in Aperture's own configuration, in its `grants`
  section, and have no `dst`. They do not go in the tailnet policy file. The
  tailnet policy for tailkeep itself (network grants and the
  tailkeep capability for each person) is in `examples/policy.example.hujson`.
- The hook payload carries the end user's `login_name` and `stable_node_id`.
  tailkeep looks the device up by that stable node ID and checks that its
  login (or, for a tagged device, its tags) matches `login_name`. A mismatch
  is blocked and audited as an integrity error.
- The end user's device must be visible to the tailkeep node, which means the
  tailnet policy needs a network grant from each person (and from
  `tag:ci-agent`) to `tag:tailkeep` on port 443. A device tailkeep cannot see
  is blocked with the reason "device not visible to tailkeep".

## 4. Check it

1. Run `tailkeep doctor`, so both certificates are fetched before the first
   request, then `tailkeep serve`.
2. Send an OpenAI chat completions request that contains a fake key
   (`<FAKE_AWS_KEY>`) to the cloud model through Aperture. A person whose
   action is `reroute` gets a 451 block that names the detector and the local
   model; a person whose action is `block` gets a 451 block without the
   guidance.
3. Send the same request with `model` set to the local model. Aperture routes
   it to the `local` provider; the hook allows it.
4. Open the tailkeep audit page. Each request has a row with the caller (the
   Aperture device), the end user, the action and the detector names. The
   scanned text is never stored.

## Limits

- Only the request is scanned. Aperture guardrails do not see responses, MCP
  tool calls or connector traffic.
- Large embedded binary data (base64 images and files of 1 KB or more that
  do not decode to text) is not scanned, so a secret inside an image or an
  uploaded file is not detected. JSON object keys are not scanned. A request
  body that repeats a key is blocked.
- A `redact` rewrite changes earlier messages in the body, which can reduce
  the provider's prompt-cache hits.
- The hook limit for a request is 10 MB; larger requests get a 413 answer,
  which `fail_closed` turns into a block.
