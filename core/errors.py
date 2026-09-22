"""Base errors for medical-privacy-guard.

All guard-specific errors inherit from GuardError so callers can catch a single
exception type while still inspecting more specific variants.
"""


class GuardError(Exception):
    """Base exception for all guard-internal failures."""


class ParserError(GuardError):
    """Raised when an input cannot be parsed.

    Per the fail-closed invariant, parsing failures should lead to a BLOCK
    decision unless an explicit policy overrides the behavior.
    """


class PolicyError(GuardError):
    """Raised when policy configuration is invalid, missing, or inconsistent."""


class VerificationError(GuardError):
    """Raised when post-sanitization verification fails."""


class AuditError(GuardError):
    """Raised when the audit writer cannot record an event.

    In strict profiles this is treated as a BLOCK condition.
    """


class TransformerError(GuardError):
    """Raised when a transformation operation is unknown or cannot be applied."""


class DictionaryError(GuardError):
    """Raised when an institution dictionary cannot be loaded or is invalid.

    Fail closed, for the same reason policy configuration does: a dictionary
    the deployment believes is active but which silently loaded nothing is
    worse than no dictionary at all.
    """
