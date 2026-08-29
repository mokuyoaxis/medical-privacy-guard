"""medical-privacy-guard: local-first privacy guardrails for medical data.

Public entry point:

    from medical_privacy_guard import Guard

    guard = Guard(profile="external-ai-strict")
    result = guard.evaluate(
        payload=text,
        recipient="external-ai",
        purpose="EXTERNAL_AI_ASSISTANCE",
    )
"""

from .guard import Guard

__version__ = "0.1.0.dev0"

__all__ = ["Guard", "__version__"]
