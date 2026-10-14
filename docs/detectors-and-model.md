# Detectors and the local model

The built-in detectors, the local classifier, its setup and the evidence for the model choice. [Back to the README](../README.md)

## Detectors

The built-in detectors are regular expressions, plus one linear scan for private keys. They always run on the full text, whatever its length. There is no entropy check.

| Detector | Finds |
|---|---|
| `aws_access_key` | `AKIA` or `ASIA` followed by 16 uppercase letters or digits |
| `private_key` | a `-----BEGIN ... PRIVATE KEY-----` header through the next `-----END ... PRIVATE KEY-----` line (any private key END marker). A header with no END line is a finding on its own |
| `github_token` | `ghp_`, `gho_` or `ghs_` followed by 36 or more characters, and `github_pat_` followed by 22 or more |
| `slack_token` | `xoxa-`, `xoxb-`, `xoxp-` or `xoxr-` followed by 10 or more characters |
| `openai_style_key` | `sk-` followed by 20 or more characters |
| `tailscale_key` | `tskey-` followed by 10 or more characters |
| `jwt` | three base64url segments, the first starting with `eyJ` |
| `conn_string_password` | the password part of a URL that has credentials before the host (a colon between user and password, then `@`). The user can be empty. A `/` inside the password ends the match, so passwords with an unencoded `/` are missed |

Other secret formats are not detected, for example `ghu_` and `ghr_` GitHub tokens, `xoxs-` Slack tokens and PGP private key blocks. A real scanner will cover more.

A finding records the detector name, its position and a preview: at most the first four characters, and never more than half of the secret. The audit log and the UI never store or show a full secret. Redaction replaces each finding with `[REDACTED:<detector>]`; findings that overlap or touch are merged so no part of a secret survives.

## The local model

The model check looks for sensitive content that patterns cannot recognize: customer data, personal details, internal hostnames and infrastructure details, and unreleased financials. Credentials are the detectors' job, so the classifier prompt does not ask about them.

- **Length limit: 2,000 characters.** Longer text is classified on the first 2,000 characters only. The result says so in its reason, but the scan response does not show that note, so treat the limit as fixed. The detectors still read the whole text.
- **It is best effort.** The detectors are the guarantee. The model check can only make a decision stricter: a `clean` answer never overrides a detector finding, and the model is not asked at all when a detector already found something. Text can contain instructions aimed at the classifier, so the text is wrapped in markers with an instruction to treat it as data, and any run of three `<` or `>` in the text is shortened so it cannot forge a marker. This lowers the risk. It does not remove it: see the injection sample in [Why this model](#why-this-model).
- **It can be talked out of a verdict.** The classifier is a model, and text inside the input can change its answer (prompt injection). In the live run an injection sample that told it to answer clean did exactly that. So it is never the only protection: the detectors run first, and block and redact decisions on found secrets do not depend on it.
- **`unknown` is its own result.** A timeout (20 seconds by default), a transport error, a bad status or an answer that cannot be parsed gives `unknown`, with a cause in the reason. It is never recorded as `clean` and never as `sensitive`. The policy field `on_unknown` decides what `unknown` does, and defaults to `block`.
- **`sensitive` with no spans.** If only the model flagged the text there is nothing to redact, so a `redact` action becomes `block` with the reason "flagged by the local model; nothing specific to redact".
- **The model's own explanation is dropped.** Its free-text reason can repeat the text it read, so it goes into no response, no audit entry and no message. Only the label and the fixed category names are kept.
- **It runs only when needed.** The web app asks the model only when the caller's policy has `model_check` on and no detector found anything. On the Aperture path the check is off by default: a classifier call through the model node takes a median of about 1.1 s, about 7 s on the first call, too slow to fit reliably in Aperture's recommended 0.5 to 2 s hook timeout.

The classifier and the answers are served by the local model through the model node, never directly from `127.0.0.1`.

## Local model setup and context size

The local model's context is 4,096 tokens. On the author's 4 GB GPU, a context of 8,192 did not fit entirely on the GPU, and 4,096 with flash attention and an 8-bit key-value cache did. The Ollama settings used:

```
OLLAMA_CONTEXT_LENGTH=4096
OLLAMA_FLASH_ATTENTION=1
OLLAMA_KV_CACHE_TYPE=q8_0
```

Leave `OLLAMA_HOST` at its default (`127.0.0.1:11434`). The model node is the only way in.

Because of the 4,096-token context, `POST /api/answers` sends the model at most 8,000 characters of the text. If the text is longer, the model answers from the first 8,000 characters and the response says so in a `note` ("answered using the first N of M characters"); tailkeep does not rely on Ollama truncating silently. The cap counts characters, not tokens, so dense text such as CJK or base64 can still exceed the context. The question is also checked for secrets, and it comes first in the text the classifier reads, so a long question narrows the classifier's 2,000-character window over the text.

For the same reason the local model's answer is capped at 512 tokens.

## A note on `block`

A note on `block`. "Block" means the text is not sent to any model for an answer. It does not mean no model reads it: when `model_check` is on, the local classifier reads the first 2,000 characters of the text to reach its decision, even for a caller whose action is `block`. That classifier, on this tailnet, is the only model that sees it. A caller who wants no model to see it at all can set `model_check` to `false` in their grant.

## Why this model

The local model is `granite4.1:3b`, served by Ollama. The model check was tried on 20 labelled texts, each 2,000 characters or less: 10 sensitive (customer records, personal details, internal hostnames and infrastructure, unreleased figures, and one text that tells the classifier to answer "clean") and 10 clean (ordinary code, documentation that mentions "API key" or "password" without containing one, public examples). No sample is only a credential, since the detectors own those. The test is `TestClassifierCheck` in `internal/classify`.

Runs 1 and 2 went directly to the local Ollama. Run 3 went through the model node.

| Run | Prompt | Correct | False positives | False negatives | Recall on the 10 sensitive | Median per call |
|---|---|---|---|---|---|---|
| 1 | first version | 15 of 20 | 0 | 5 | 5 of 10 | 1.46 s |
| 2 | category names added | 17 of 20 | 0 | 3 | 7 of 10 | 1.35 s |
| 3 (through the model node) | same as run 2 | 17 of 20 | 0 | 3 | 7 of 10 | 1.11 s |

In run 2 the model missed the customer records, the internal infrastructure text and the injection sample. Recall on sensitive text is 7 of 10, so the model check misses things. It raised no false alarm on the 10 clean samples in either run, which is a small sample. By design the model check can only make a decision stricter, so a miss leaves the detectors' result in place; do not rely on it for completeness. The first (cold) call was slow: 7.05 s in run 1, 5.6 s in run 2 and about 6.8 s in run 3, while the model loads. The model is not fully deterministic at temperature 0, so treat single runs as indicative.

**The injection sample** (a sensitive text that tells the classifier to answer "clean") was classified `clean` in all three runs. The model check can be talked out of a verdict by the text it reads. That is one reason it can only tighten a decision, and why the detectors, not the model, are the guarantee for credentials.

A fake key inside 2,000 characters was flagged in 4 of 5 runs in an earlier test and in 0 of 5 runs at 6,000 characters, which is why the limit is 2,000.
