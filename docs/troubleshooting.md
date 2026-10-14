# Troubleshooting

[Back to the README](../README.md)

**`ollama ps` does not show `100% GPU`.** `CUDA_VISIBLE_DEVICES` takes the GPU UUID from `nvidia-smi -L`. Otherwise the context may be too large for the card. See [Local model setup and context size](detectors-and-model.md#local-model-setup-and-context-size). `ollama ps` lists a model only for a few minutes after its last use.

**Installing Ollama.** `tailkeep doctor` prints the route for your system. On Linux it is Ollama's install script from their download page. For Windows and macOS it prints the download page URL for those systems: `https://ollama.com/download/windows` ("Download Ollama on Windows") and `https://ollama.com/download/mac` ("Download Ollama on macOS"). Ollama's download page (`https://ollama.com/download`) is the reference.

**`doctor` or `serve` fails to start a node.** On the first start both `TS_AUTHKEY_GUARD` and `TS_AUTHKEY_LLM` must be set, to reusable, pre-approved, tagged keys. An ephemeral node is deleted when it stops, so a restart needs a new registration and a key that can be used again; a key created without "Reusable" fails the second start with "not valid". Also check that no machine with those names already exists.

**HTTPS certificates and MagicDNS.** Both must be enabled in the admin console (DNS page). The first certificate for each name takes about 31 to 35 seconds; run `doctor` once so they are fetched before the first request. If the certificate authority rate limits your tailnet, wait and run `doctor` again. Machine names become public in certificate transparency logs once certificates are issued; check they are names you are happy to publish.

**403 from the web app.** The `Host` header must be the bare MagicDNS name of the guard. An IP address, a short name or a proxy that rewrites `Host` is refused. A `POST` must also be `Content-Type: application/json`.

**The hook says "device not visible to tailkeep", or the web app says "caller could not be identified".** The guard can only look up devices in its own peer list, which depends on network grants. Add a grant from the person's devices (and from `tag:ci-agent`) to `tag:tailkeep` on port 443.

**A request is blocked as "malformed capability".** One grant carrying the tailkeep capability has invalid JSON, a wrong type, an unknown value, or an unknown field. The whole capability is denied. The reason is in the guard's log.

**The model node answers 403.** The caller does not hold the `llm` capability toward `tag:tailkeep-llm`. The response names the caller. A network grant to port 443 is also needed to connect.

**Aperture blocks every request, including chat.** If the hook is configured with `fail_policy: fail_closed` and tailkeep is not running, or Aperture cannot reach it, every request is blocked until tailkeep is back or the hook entry is removed. This is the intended behavior of `fail_closed`.

**A rerouted request is refused by Aperture.** The person's Aperture grant must allow the local model as well as the cloud model. The local provider must serve the request's API format: tailkeep's model node serves OpenAI chat completions only. The model name in the request must match the one in Aperture's provider (`granite4.1:3b` by default; change it with `--model`).

**The base URL has `/v1` twice.** The local provider's base URL in Aperture is `https://tailkeep-llm.<tailnet>.ts.net` with no `/v1`. Aperture adds the request path itself.

**A model listed under two Aperture providers goes to the wrong one.** Give the provider you want a higher `preference`, and check Aperture's logs to see which provider answered. A short Aperture name such as `http://aperture/` may not resolve until the Tailscale client is installed on the device you test from.

**Aperture shows two instances.** A Tailscale-hosted Aperture can appear as two untagged machines with separate configurations. Tag the one that holds your providers with `tag:aperture`, and grant that tag; an untagged Aperture would share your own identity. Grants whose destination names a user or machine stop matching once the machine is tagged.

**Aperture's reply is a 451 you did not expect.** The message names the detector or category. Check the end user's action in the policy file. A `reroute` user always sees a block with guidance (see [Using it with Aperture](aperture.md#using-it-with-aperture)).

**Policy changes take a while to apply.** Grants are read on each request, so no restart is needed, but a change in the admin console takes some time to reach the nodes. In one live check it took about 1 to 2 seconds (approximate, one check).

**Running `doctor` and `serve` together.** Both use the same state directory and node state. Stop `serve` before running `doctor`.

## Notes from the quick start

Longer notes that the README's quick start leaves out.

**Auth keys.** After the first start the state directory holds the node keys and the variables are no longer needed. Both nodes are persistent, so their names stay stable. Before the first start, check that no machine called `tailkeep` or `tailkeep-llm` exists in your tailnet: the names are expected to appear in public certificate transparency logs once certificates are issued.

**Ollama and the model.** Install Ollama and pull `granite4.1:3b`. `tailkeep doctor` tells you which step is missing (below).

**Doctor.** It stops at the first failure and prints a fix. The checks run in this order: Ollama reachable, model installed, model answers (it prints the time, so you know what speed to expect), both nodes start, a certificate for each name, WhoIs on each node, and the guard calling the model node over the tailnet (this proves the `llm` grant). If Ollama is missing it prints the install route for your operating system as text to copy. It never downloads or runs an installer and never runs a command for you. If the model is missing it prints `ollama pull <model>`; with `--pull-model` it asks the local Ollama to pull the model (loopback addresses only).

**Serve.** Open `https://tailkeep.<tailnet>.ts.net`. The page shows who you are and which policy applies to you. Paste text, press Check, and if the action is not `block`, ask a question about it. The audit page is at `/audit`.
