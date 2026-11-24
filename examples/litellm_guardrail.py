"""LiteLLM custom guardrail backed by medical-privacy-guard.

Register this class in a LiteLLM proxy config (see
docs/litellm-deployment.md) and every request text is decided by the
guard before it reaches the model provider:

- ALLOW    -> the text passes unchanged
- SANITIZE -> the text is replaced by its transformed form
- ASK      -> the call is rejected: a proxy has no human approver, so an
              ASK is never silently released (use the grant flow through
              the Python API or the chained gateway where approval lives)
- BLOCK    -> the call is rejected

Rejection messages carry reason codes only, never the detected values.

The `recipient` parameter states the trust level of the provider
endpoint behind LiteLLM: a contracted, vetted provider is
`external_approved` (the default); an unvetted endpoint is
`external_unknown`, under which medical content escalates to ASK and is
therefore rejected by this guardrail. That is the fail-closed design,
not a malfunction.

Requires: pip install "litellm==1.108.0" medical-privacy-guard
(the example is verified against LiteLLM 1.108.0, the 1.108 LTS line;
never deploy LiteLLM 1.107.0 — see docs/litellm-deployment.md)
"""

from typing import Literal, Optional

from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.types.utils import GenericGuardrailAPIInputs

from medical_privacy_guard import Guard
from medical_privacy_guard.core.model import Verdict


class MedicalPrivacyGuardrail(CustomGuardrail):
    """Run medical-privacy-guard over LiteLLM request texts (pre_call)."""

    def __init__(
        self,
        profile: str = "external-ai-strict",
        recipient: str = "external_approved",
        purpose: str = "external_ai_assistance",
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._guard = Guard(profile=profile)
        self._recipient = recipient
        self._purpose = purpose

    async def apply_guardrail(
        self,
        inputs: GenericGuardrailAPIInputs,
        request_data: dict,
        input_type: Literal["request", "response"],
        logging_obj: Optional[object] = None,
    ) -> GenericGuardrailAPIInputs:
        # Requests only: responses are the provider's text, not data the
        # sender chose to disclose, and this guard does not inspect them.
        if input_type != "request":
            return inputs
        texts = inputs.get("texts") or []
        if texts:
            inputs["texts"] = [self._guard_text(text) for text in texts]
        return inputs

    def _guard_text(self, text: str) -> str:
        result = self._guard.sanitize(text, self._recipient, self._purpose)
        decision = result.decision_before
        codes = ", ".join(
            getattr(code, "value", str(code)) for code in decision.reason_codes
        )
        if decision.verdict is Verdict.ASK:
            raise Exception(
                "medical-privacy-guard: this request needs human approval "
                f"(ASK: {codes}); a LiteLLM proxy cannot approve it, so the "
                "call is rejected. Route approval through the grant flow."
            )
        if decision.verdict is Verdict.BLOCK or result.sanitized_payload is None:
            raise Exception(
                f"medical-privacy-guard: request blocked ({codes})"
            )
        return result.sanitized_payload.content
