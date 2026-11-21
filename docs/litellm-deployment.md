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

## Shape A — chained gateway (no code)

Run the guard's HTTP gateway in front of the LiteLLM proxy. Clients
talk to the guard; the guard sanitizes or withholds, then forwards to
LiteLLM as its fixed upstream.

```bash
# 1. LiteLLM proxy, as usual (providers, keys, routing live here)
litellm --config litellm-config.yaml --port 4000

# 2. The guard in front of it
medical-privacy-guard serve \
    --upstream http://127.0.0.1:4000 \
    --profile external-ai-strict \
    --port 8787
```

Clients change only their base URL:

```python
client = OpenAI(base_url="http://127.0.0.1:8787/v1", api_key="...")
```

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
LiteLLM custom guardrail. The complete, tested implementation is
[examples/litellm_guardrail.py](../examples/litellm_guardrail.py);
the registration in `litellm-config.yaml` is:

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
pip install litellm medical-privacy-guard
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

## Which shape

- Default to Shape A: one binary to run, the whole payload in view,
  approvals and audit in their designed place.
- Choose Shape B when LiteLLM is already the mandated front door and
  per-request, in-process masking inside it is the requirement.

Under both shapes the same statement holds: the guard is an engineering
control, not a compliance guarantee and not a disclosure authorization.
