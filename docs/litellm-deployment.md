# Deploying with LiteLLM

LiteLLM is a common front door for model traffic: one proxy, many
providers, OpenAI-shaped requests. It is also exactly the boundary this
guard exists for — the last hop before clinical text leaves the
institution. There are two ways to put the guard on that boundary. Both
keep detection, decisions and audit on your side of it.

LiteLLM ships its own PII guardrail options (Presidio among them). What
this guard adds is a decision, not just a mask: four verdicts
(ALLOW / SANITIZE / ASK / BLOCK), Chinese clinical detectors,
post-transformation verification, and a tamper-evident audit chain.

## Pin the LiteLLM version first

Every command in this guide assumes **LiteLLM 1.108.0**, the first
release of the 1.108 LTS line (November 2026). The LTS line receives
patch releases as 1.108.x; moving along it is a deliberate upgrade —
pin the exact version, re-run the walkthrough below, then roll out.

```bash
pip install "litellm==1.108.0"
# or, as a container: ghcr.io/berriai/litellm:v1.108.0
```

> **Never deploy LiteLLM 1.107.0.** That release was a supply-chain
> compromise: on 21 October 2026 the release pipeline was hijacked and
> every 1.107.0 wheel on PyPI carried a credential stealer. PyPI has
> removed the release, and during the exposure window the floating
> Docker tags (`latest`, `main-latest`, `main-stable`) pointed at the
> compromised image. Pinning an exact version — and never floating on
> a tag — is what keeps a repeat of that incident from becoming your
> incident. If a 1.107.0 install is found anywhere, treat every key it
> could read as stolen and rotate them.

## Shape A — chained gateway (no code)

Run the guard's HTTP gateway in front of the LiteLLM proxy. Clients
talk to the guard; the guard sanitizes or withholds, then forwards to
LiteLLM as its fixed upstream.

### 1. Configure and start LiteLLM

A minimal `litellm-config.yaml` — providers, keys and routing live
here, as usual:

```yaml
model_list:
  - model_name: clinical-chat
    litellm_params:
      model: openai/<your-model>
      api_key: os.environ/OPENAI_API_KEY
```

```bash
pip install "litellm==1.108.0"
litellm --config litellm-config.yaml --port 4000
```

### 2. Start the guard in front of it

```bash
medical-privacy-guard serve \
    --upstream http://127.0.0.1:4000 \
    --profile external-ai-strict \
    --port 8787
```

Check the gateway is up (this endpoint is unauthenticated and returns
no configuration):

```bash
curl http://127.0.0.1:8787/healthz
# {"status":"ok","service":"medical-privacy-guard"}
```

### 3. Send a guarded request

Clients change only their base URL:

```python
client = OpenAI(base_url="http://127.0.0.1:8787/v1", api_key="...")
```

A request carrying a phone number is sanitized before LiteLLM sees
it. With synthetic data:

```bash
curl -X POST http://127.0.0.1:8787/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"clinical-chat","messages":[{"role":"user",
       "content":"患者复诊，联系电话13800000000"}]}'
```

The request is forwarded, and what LiteLLM receives is the transformed
text — the raw number never crosses the boundary:

```text
患者复诊，联系电话[REDACTED]
```

A request carrying a government ID is withheld outright. The client
gets HTTP 403 with reason codes and risk metadata — never payload
text — and nothing is forwarded:

```bash
curl -X POST http://127.0.0.1:8787/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"clinical-chat","messages":[{"role":"user",
       "content":"身份证号110101199003078888"}]}'
```

```json
{"error":{"message":"Request withheld by medical privacy guard (BLOCK)",
"type":"privacy_guard_block","code":"BLOCK",
"reason_codes":["GOVERNMENT_ID_PRESENT"],"risk_level":"HIGH",
"risk_score":75,"policy_version":"external-ai-strict/1"}}
```

(The ID above is a synthetic test value, as is the phone number.)

What you get with this shape:

- The full payload is evaluated as one unit (all messages together),
  not text fragment by text fragment.
- ASK verdicts are withheld with a `privacy_guard_ask` error; where an
  approval flow is configured, grants can release them (see
  [approval-workflow.md](approval-workflow.md)).
- The audit chain records every decision locally. LiteLLM never sees
  the raw text of a blocked request — it is rejected before forwarding.

## Shape B — a LiteLLM custom guardrail (in-process)

If LiteLLM must stay the outermost layer, register the guard as a
LiteLLM custom guardrail. The complete implementation is
[examples/litellm_guardrail.py](../examples/litellm_guardrail.py),
verified against LiteLLM 1.108.0 (the LTS line above); the
registration in `litellm-config.yaml` is:

```yaml
model_list:
  - model_name: clinical-chat
    litellm_params:
      model: openai/<your-model>
      api_key: os.environ/OPENAI_API_KEY

guardrails:
  - guardrail_name: "medical-privacy-guard"
    litellm_params:
      guardrail: litellm_guardrail.MedicalPrivacyGuardrail
      mode: pre_call            # masking only works pre_call
      default_on: true          # clients need not opt in per request
      profile: external-ai-strict
      recipient: external_approved
      purpose: external_ai_assistance
```

Start the proxy from the directory holding `litellm_guardrail.py`:

```bash
pip install "litellm==1.108.0" medical-privacy-guard
litellm --config litellm-config.yaml --port 4000
```

How verdicts map inside the proxy:

| Verdict | Behaviour |
|---|---|
| ALLOW | Text passes unchanged |
| SANITIZE | The extracted text is replaced by its transformed form before the provider call |
| ASK | The call is rejected with the reason codes — a proxy has no human approver, so an ASK is never silently released |
| BLOCK | The call is rejected with the reason codes |

Rejection messages carry reason codes only, never detected values.

### The recipient setting is a deployment decision

`recipient` states the trust level of the provider endpoint behind
LiteLLM, and it changes outcomes:

- A contracted, vetted provider: `external_approved` (the example
  default). Identifiers are sanitized; clinical content flows.
- An unvetted endpoint: `external_unknown`. Medical content escalates
  to ASK — and is therefore rejected by this guardrail — and a
  government ID is a hard BLOCK. If every request comes back rejected
  under this setting, the setting is doing its job; do not "fix" it by
  quietly upgrading trust.

### Limits of this shape

LiteLLM hands the guardrail the texts it extracts from a request, so
each text is decided on its own; cross-message context is not part of
the decision. Responses are not inspected (the guardrail returns them
unchanged), matching the gateway boundary in [scope.md](scope.md).
When either limitation matters, use Shape A.

## A note on LiteLLM's Presidio option

If you also run LiteLLM's built-in Presidio masking, deploy Presidio
from its current home. Presidio is no longer a Microsoft project: it
moved to the community Data Privacy Stack organisation in 2026, and
official container images are published to GHCR:

```bash
docker pull ghcr.io/data-privacy-stack/presidio-analyzer:2.2.366
docker pull ghcr.io/data-privacy-stack/presidio-anonymizer:2.2.366
```

Pin a release tag from the package page, as above. LiteLLM's Presidio
tutorial still shows the legacy `mcr.microsoft.com/presidio-*`
images; those are no longer updated and should not be used for a new
deployment.

## Which shape

- Default to Shape A: one binary to run, the whole payload in view,
  approvals and audit in their designed place.
- Choose Shape B when LiteLLM is already the mandated front door and
  per-request, in-process masking inside it is the requirement.

Under both shapes the same statement holds: the guard is an engineering
control, not a compliance guarantee and not a disclosure authorization.
