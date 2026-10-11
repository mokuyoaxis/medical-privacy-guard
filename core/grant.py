"""Scoped, expiring approval grants for the ASK verdict.

The decision protocol has four verdicts. ALLOW, SANITIZE and BLOCK are all
end-to-end paths: the guard produces a payload, withholds it, or refuses. ASK
was the one that stopped in the middle — it withheld the payload and the caller
was told "a scoped grant is required", with nothing in the library able to say
what a grant is. This module closes that gap.

It deliberately does **not** decide who may approve. ``docs/scope.md`` already
states that the library is not an authorization service for self-declared
``EXTERNAL_APPROVED`` values; the same holds here. The guard does three things:

1. describe what needs approving (:class:`ApprovalRequest`, no raw values);
2. check whether a submitted :class:`Grant` authorizes *this* disclosure;
3. consume the grant and record that a granted release happened.

Issuing is deployment-side (:class:`GrantIssuer`) and needs a key the payload
being authorized cannot hold — otherwise a document could authorize itself.

Design: ``.internal/ask-grant-plan-2026-10-03.md``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any, Mapping, Sequence

from .errors import GrantError
from .model import Decision, DetectedFact, Purpose, Recipient

__all__ = [
    "GRANT_KEY_ENV",
    "ApprovalRequest",
    "Grant",
    "GrantIssuer",
    "GrantRegistry",
    "approval_request_for",
    "content_hash",
    "env_grant_key",
]

#: Environment variable holding the grant-signing key. Read from the
#: environment rather than a parameter default so a key never lands in argv.
GRANT_KEY_ENV = "MEDICAL_PRIVACY_GUARD_GRANT_KEY"

_ISO = "%Y-%m-%dT%H:%M:%S.%fZ"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: str) -> datetime:
    try:
        return datetime.strptime(value, _ISO).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise GrantError(f"invalid timestamp {value!r}") from exc


def env_grant_key() -> bytes | None:
    """Return the configured grant key from the environment, if any."""
    import os

    raw = os.environ.get(GRANT_KEY_ENV)
    return raw.encode("utf-8") if raw else None


def content_hash(payload_kind: str, content: Any) -> str:
    """Hash a payload's content so a fingerprint can bind without disclosing it.

    The fingerprint must pin a grant to one exact payload without carrying the
    payload into the grant, the request or the audit. A hash does both: change
    one byte and every previously issued grant stops matching.
    """
    if isinstance(content, str):
        raw = content.encode("utf-8")
    else:
        # A structured payload is hashed through its JSON form so two equal
        # documents hash alike regardless of key order or Python type.
        raw = json.dumps(content, ensure_ascii=False, sort_keys=True).encode(
            "utf-8"
        )
    return hashlib.sha256(f"{payload_kind}\x00".encode("utf-8") + raw).hexdigest()


def _canonical(data: Mapping[str, Any]) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


@dataclass(frozen=True)
class ApprovalRequest:
    """What needs human approval. Contains no raw sensitive values.

    The guard builds one whenever it returns ASK. A caller shows it to a human
    (or to the deployment's approval service) and gets a :class:`Grant` back.
    """

    request_id: str
    fingerprint: str
    verdict: str
    reason_codes: tuple[str, ...]
    risk_level: str
    risk_score: int
    fact_counts: Mapping[str, int]
    recipient_class: str
    purpose: str
    policy_version: str
    created_at: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "request_id": self.request_id,
                "fingerprint": self.fingerprint,
                "verdict": self.verdict,
                "reason_codes": list(self.reason_codes),
                "risk_level": self.risk_level,
                "risk_score": self.risk_score,
                "fact_counts": dict(self.fact_counts),
                "recipient_class": self.recipient_class,
                "purpose": self.purpose,
                "policy_version": self.policy_version,
                "created_at": self.created_at,
            },
            ensure_ascii=False,
            sort_keys=True,
        )


@dataclass(frozen=True)
class Grant:
    """A deployment-issued authorization for one disclosure.

    Every field below except ``signature`` is covered by the signature, so a
    grant cannot be edited after issue: not its expiry, not its allowed uses,
    not the types the human agreed to accept.
    """

    grant_id: str
    request_fingerprint: str
    issuer: str
    issued_at: str
    expires_at: str
    uses_allowed: int = 1
    #: Fact types the human explicitly accepted the risk of. A type that is
    #: untransformable in the released payload must be listed here; the grant
    #: carries residual risk, it does not switch protection off.
    accepted_types: tuple[str, ...] = ()
    signature: str = ""

    def __post_init__(self) -> None:
        for field in ("grant_id", "request_fingerprint", "issuer", "issued_at", "expires_at"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value:
                raise GrantError(f"grant {field} must be a non-empty string")
        if not isinstance(self.signature, str):
            raise GrantError("grant signature must be a string")
        if type(self.uses_allowed) is not int or self.uses_allowed < 1:
            raise GrantError("grant uses_allowed must be a positive integer")
        if not isinstance(self.accepted_types, tuple) or any(
            not isinstance(value, str) or not value for value in self.accepted_types
        ):
            raise GrantError("grant accepted_types must be a tuple of non-empty strings")

    # -- serialization ------------------------------------------------------

    def _payload(self) -> dict:
        return {
            "grant_id": self.grant_id,
            "request_fingerprint": self.request_fingerprint,
            "issuer": self.issuer,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "uses_allowed": self.uses_allowed,
            "accepted_types": list(self.accepted_types),
        }

    def to_json(self) -> str:
        return json.dumps({**self._payload(), "signature": self.signature},
                          ensure_ascii=False, sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "Grant":
        try:
            data = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise GrantError("grant is not valid JSON") from exc
        if not isinstance(data, dict):
            raise GrantError("grant must be a JSON object")
        accepted = data.get("accepted_types", [])
        if not isinstance(accepted, list):
            raise GrantError("grant accepted_types must be an array")
        try:
            return cls(
                grant_id=data["grant_id"],
                request_fingerprint=data["request_fingerprint"],
                issuer=data["issuer"],
                issued_at=data["issued_at"],
                expires_at=data["expires_at"],
                uses_allowed=data.get("uses_allowed", 1),
                accepted_types=tuple(accepted),
                signature=data.get("signature", ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GrantError("grant is missing or has invalid fields") from exc

    # -- signing ------------------------------------------------------------

    def signed(self, key: bytes) -> "Grant":
        """Return a copy carrying an HMAC over its canonical fields."""
        return replace(
            self, signature=hmac.new(key, _canonical(self._payload()), hashlib.sha256).hexdigest()
        )

    def signature_is_valid(self, key: bytes) -> bool:
        if not self.signature.isascii():
            return False
        expected = hmac.new(key, _canonical(self._payload()), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature)


def approval_request_for(
    *,
    decision: Decision,
    facts: Sequence[DetectedFact],
    recipient: Recipient,
    purpose: Purpose,
    payload_kind: str,
    content: Any,
    key: bytes,
    request_id: str | None = None,
) -> ApprovalRequest:
    """Build the ApprovalRequest for a decision, bound to this exact disclosure.

    The fingerprint covers the payload, the recipient, the purpose, the policy
    version and the decision itself. A grant is therefore valid for one
    disclosure of one payload to one endpoint for one purpose — not for "this
    kind of document from now on".
    """
    counts: dict[str, int] = {}
    for fact in facts:
        counts[fact.type] = counts.get(fact.type, 0) + 1

    fingerprint_material = {
        "payload_kind": payload_kind,
        "content_hash": content_hash(payload_kind, content),
        "recipient_trust": recipient.trust_level.value,
        "recipient_name": recipient.name or "",
        "recipient_endpoint": recipient.endpoint or "",
        "purpose": purpose.value,
        "policy_version": decision.policy_version,
        "verdict": decision.verdict.value,
        "reason_codes": sorted(rc.value for rc in decision.reason_codes),
        "fact_types": sorted(counts),
    }
    fingerprint = hmac.new(key, _canonical(fingerprint_material), hashlib.sha256).hexdigest()

    return ApprovalRequest(
        request_id=request_id or uuid.uuid4().hex,
        fingerprint=fingerprint,
        verdict=decision.verdict.value,
        reason_codes=tuple(rc.value for rc in decision.reason_codes),
        risk_level=decision.risk.level.value,
        risk_score=decision.risk.score,
        fact_counts=counts,
        recipient_class=recipient.trust_level.value,
        purpose=purpose.value,
        policy_version=decision.policy_version,
        created_at=_now().strftime(_ISO),
    )


class GrantIssuer:
    """Issues grants. Deployment-side: it holds the key, the payload does not.

    A grant is useless without the key, and the key never travels with the data
    being authorized. That is what makes "cannot be issued by the payload it
    authorizes" true rather than merely asserted.
    """

    def __init__(self, key: bytes, issuer: str) -> None:
        if not key:
            raise GrantError("a grant issuer requires a non-empty key")
        self._key = key
        self.issuer = issuer

    def issue(
        self,
        request: ApprovalRequest,
        *,
        ttl_seconds: int,
        accepted_types: Sequence[str] = (),
        uses_allowed: int = 1,
        now: datetime | None = None,
    ) -> Grant:
        """Issue a grant for *request*, expiring in *ttl_seconds*.

        ``ttl_seconds`` is required rather than defaulted: an approval that
        never expires is a blanket allow, which is the thing this design exists
        to prevent.

        An explicit clock value must be timezone-aware; timestamps are stored
        in UTC regardless of the supplied offset.
        """
        if type(ttl_seconds) is not int or ttl_seconds <= 0:
            raise GrantError("ttl_seconds must be a positive integer; an approval must expire")
        moment = now or _now()
        if moment.utcoffset() is None:
            raise GrantError("grant issuance time must be timezone-aware")
        moment = moment.astimezone(timezone.utc)
        grant = Grant(
            grant_id=uuid.uuid4().hex,
            request_fingerprint=request.fingerprint,
            issuer=self.issuer,
            issued_at=moment.strftime(_ISO),
            expires_at=(moment + timedelta(seconds=ttl_seconds)).strftime(_ISO),
            uses_allowed=uses_allowed,
            accepted_types=tuple(accepted_types),
        )
        return grant.signed(self._key)


class GrantRegistry:
    """Consumes grants so a one-time approval cannot be replayed.

    A lock protects the read/update so concurrent callers share one use budget.
    Guard instances share one registry by default. The store is in-memory: it
    does not survive a restart and is not shared between processes. A deployment
    that needs durable single-use injects a registry whose consume operation is
    atomic in its persistent store. An explicitly supplied registry defines its
    own consumption scope.
    """

    def __init__(self) -> None:
        self._used: dict[str, int] = {}
        self._lock = Lock()

    def remaining(self, grant_id: str) -> int:
        """Return recorded uses (the legacy method name does not mean uses left)."""
        with self._lock:
            return self._used.get(grant_id, 0)

    def consume(self, grant: Grant, store: "dict[str, int] | None" = None) -> bool:
        """Record one use of *grant*. False when it has been used up."""
        target = self._used if store is None else store
        with self._lock:
            used = target.get(grant.grant_id, 0)
            if used >= grant.uses_allowed:
                return False
            target[grant.grant_id] = used + 1
            return True


def check_grant(
    grant: Grant,
    request: ApprovalRequest,
    *,
    key: bytes,
    untransformable_types: Sequence[str] = (),
    now: datetime | None = None,
) -> str | None:
    """Return None when *grant* authorizes *request*, else the reason it does not.

    Every failure returns a reason rather than raising, because a rejected grant
    is not an error: it falls back to ASK. Nothing here can turn a bad grant
    into an ALLOW.
    """
    if not key:
        return "no grant key is configured"
    if not grant.signature:
        return "grant is not signed"
    if not grant.signature_is_valid(key):
        return "grant signature does not verify"
    if not grant.request_fingerprint.isascii() or not hmac.compare_digest(
        grant.request_fingerprint, request.fingerprint
    ):
        return "grant was issued for a different disclosure"
    moment = now or _now()
    if moment.utcoffset() is None:
        return "grant evaluation time must be timezone-aware"
    try:
        issued_at = _parse_iso(grant.issued_at)
        expires_at = _parse_iso(grant.expires_at)
    except GrantError:
        return "grant timestamps are malformed"
    if issued_at > moment:
        return "grant is not yet valid"
    if expires_at <= moment:
        return "grant has expired"
    missing = sorted(set(untransformable_types) - set(grant.accepted_types))
    if missing:
        return f"grant does not accept the risk of: {', '.join(missing)}"
    return None
