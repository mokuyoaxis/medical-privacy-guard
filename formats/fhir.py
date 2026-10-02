"""FHIR resource inspection and admission.

This module covers a minimal resource set and deliberately promises no more than it
implements: this module says *which* resource a document is, whether that
resource is one the guard can walk, and where its leaves are. It does not
de-identify a FHIR document, and it does not claim that a released Bundle is
anonymous.

Two things make a FHIR payload different from the JSON it is written in:

- **A resource type is declared, and it is load-bearing.** ``{"resourceType":
  "Patient"}`` tells the guard what the fields mean before any value is read.
  A resource outside the supported set is not "unknown JSON that happens to be
  safe"; it is a document whose semantics the guard was never taught, so it
  is withheld (BLOCK) instead of being walked as generic JSON where an
  unrecognised identifier would simply not be looked for.
- **Paths are FHIR paths, not JSON Pointers.** The report names
  ``Patient.name.family`` rather than ``/name/0/family``, because that is what
  a reviewer and a downstream policy can act on. The underlying addressing is
  still the JSON Pointer the transformation writes back through, so the two
  stay in step and nothing is rewritten by a second mechanism.

The leaf collection itself is the ordinary JSON one. A second traversal would
be a second thing to keep in step, and divergence between two readers of one
document is exactly the failure shape this project keeps hitting.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from core.errors import ParserError

from .json_payload import from_document

__all__ = [
    "FHIR_RESOURCES",
    "FhirResource",
    "fhir_path_for",
    "inspect_fhir",
]

#: The resource types this version can walk. Everything else fails closed.
#:
#: Chosen because they are the resources a clinical egress path actually
#: carries, not because the list is convenient: Patient, Observation,
#: DiagnosticReport, Condition, MedicationRequest, Encounter, ImagingStudy and
#: Bundle. A Bundle is walked as its entries, so supporting it means supporting
#: whatever it contains -- an entry whose resource type is outside this set
#: fails closed on its own.
FHIR_RESOURCES: frozenset[str] = frozenset(
    {
        "Patient",
        "Observation",
        "DiagnosticReport",
        "Condition",
        "MedicationRequest",
        "Encounter",
        "ImagingStudy",
        "Bundle",
    }
)

# An unsupported resource is reported as an unsupported format, which the
# policy profiles turn into BLOCK. It used to carry a separate
# ``UNSUPPORTED_RESOURCE_VERDICT = "ASK"`` constant that nothing read; the
# constant said one thing and the guard did another, so it was removed. The
# verdict is the policy's, not this module's, to state.

#: The key a FHIR resource uses to declare its type.
_RESOURCE_TYPE_KEY = "resourceType"


@dataclass(frozen=True)
class FhirResource:
    """One resource found in a FHIR document.

    ``pointer`` addresses the resource inside the document (empty for a
    standalone resource, ``/entry/0/resource`` inside a Bundle), so every leaf
    below it can be reported with a path a reviewer can act on.
    """

    resource_type: str
    pointer: str
    supported: bool

    @property
    def verdict_note(self) -> str:
        return (
            "supported" if self.supported
            else f"unsupported resource type {self.resource_type!r}"
        )


def _resource_type_at(node: Any) -> str | None:
    """Return the declared resource type of *node*, or None."""
    if not isinstance(node, dict):
        return None
    value = node.get(_RESOURCE_TYPE_KEY)
    return value if isinstance(value, str) and value else None


def _walk_resources(document: Any) -> tuple[FhirResource, ...]:
    """Find every resource in *document*, depth-first, in document order.

    Explicitly iterative: nesting depth is attacker-controlled, and a document
    of some thousands of brackets must not become a recursion error.
    """
    found: list[FhirResource] = []
    stack: list[tuple[Any, str]] = [(document, "")]
    while stack:
        node, pointer = stack.pop()
        if isinstance(node, dict):
            rtype = _resource_type_at(node)
            if rtype is not None:
                found.append(
                    FhirResource(
                        resource_type=rtype,
                        pointer=pointer,
                        supported=rtype in FHIR_RESOURCES,
                    )
                )
            # Bundle entries nest resources that must be checked on their own
            # terms: a Bundle of an unsupported resource is not made safe by
            # the Bundle being supported.
            for key, value in reversed(list(node.items())):
                if isinstance(value, (dict, list)):
                    stack.append(
                        (value, f"{pointer}/{_escape(key)}")
                    )
        elif isinstance(node, list):
            for index in range(len(node) - 1, -1, -1):
                stack.append((node[index], f"{pointer}/{index}"))
    return tuple(found)


def _escape(token: str) -> str:
    """JSON Pointer escaping (RFC 6901) for one reference token."""
    return str(token).replace("~", "~0").replace("/", "~1")


def fhir_path_for(pointer: str) -> str:
    """Render a JSON Pointer as a FHIR path.

    ``/name/0/family`` becomes ``name.family``: array indices are dropped
    because a FHIR path names the element, not a position in it, and a report
    that said ``name.0.family`` would not match anything a reviewer or a policy
    can look up.
    """
    tokens = (token for token in pointer.split("/") if token)
    parts: list[str] = []
    for token in tokens:
        unescaped = token.replace("~1", "/").replace("~0", "~")
        if unescaped.isdigit():
            continue
        parts.append(unescaped)
    return ".".join(parts)


def inspect_fhir(document: Any) -> tuple[FhirResource, ...]:
    """Return every resource declared in *document*.

    Raises :class:`ParserError` when the document is not a FHIR object at all.
    A JSON array of resources is not rejected here: a Bundle is the usual
    container, but a caller holding a searchset's entries is still describing
    FHIR, and refusing it would push the caller toward declaring plain JSON,
    which is the divergence the shared admission rule exists to prevent.
    """
    if isinstance(document, Mapping):
        if _resource_type_at(document) is None:
            raise ParserError(
                "not a FHIR resource: no string 'resourceType' at the top level"
            )
        return _walk_resources(document)
    if isinstance(document, list):
        found: list[FhirResource] = []
        for index, item in enumerate(document):
            found.extend(
                FhirResource(
                    resource_type=rtype,
                    pointer=f"/{index}{res.pointer}",
                    supported=res.supported,
                )
                for res in _walk_resources(item)
                if (rtype := _resource_type_at(item)) is not None
            )
        return tuple(found)
    raise ParserError("FHIR payload must be an object or an array of objects")


#: HumanName component keys, in the order they are joined to form a name.
_NAME_COMPONENT_KEYS: tuple[str, ...] = ("family", "given", "middle", "prefix", "suffix")

#: Keys whose value is a whole name rather than one component of it.
_NAME_VALUE_KEYS: frozenset[str] = frozenset({"text", "fullname", "name"})


def _string_components(value: Any, path: str) -> list[tuple[str, str]]:
    """Plain-string leaves under a HumanName component, with their paths."""
    if isinstance(value, str) and value.strip():
        return [(value, path)]
    if isinstance(value, list):
        return [
            (item, f"{path}/{index}")
            for index, item in enumerate(value)
            if isinstance(item, str) and item.strip()
        ]
    return []


def _complete_names(document: Any) -> dict[str, str]:
    """Join the components of a FHIR HumanName into one probe per leaf.

    FHIR splits a person's name across ``Patient.name.family`` and
    ``Patient.name.given``, and the detectors need a whole name to see one:
    ``姓名：张`` and ``姓名：伟`` yield nothing, while ``姓名：张伟`` matches. A
    resource is therefore released with the surname intact if each component is
    only ever scanned on its own.

    The joined form is a *probe*, not a rewrite: detection sees it, and the
    replacement is still written back through each component's own path, so the
    document's structure is preserved. Every component of one HumanName shares
    the joined probe, so the whole name is reported once per component and the
    merge keeps one fact.

    Only HumanName-shaped objects are joined. A key called ``family`` elsewhere
    in a resource is left alone, because guessing at structure the standard did
    not declare is how a detector starts reading prose as people.
    """
    extra: dict[str, str] = {}
    stack: list[tuple[Any, str]] = [(document, "")]
    while stack:
        node, pointer = stack.pop()
        if isinstance(node, dict):
            # ``family`` is a string and ``given`` is an array in FHIR, so a
            # component's value may sit one level down ("given": ["伟"]).
            # Only the plain-string leaves of a component are completed, and
            # each inherits the whole joined name.
            parts: list[str] = []
            holders: list[tuple[str, str]] = []
            for key in _NAME_COMPONENT_KEYS:
                value = node.get(key)
                found = _string_components(value, f"{pointer}/{_escape(key)}")
                if not found:
                    continue
                parts.append("".join(text for text, _ in found))
                holders.extend(found)
            if len(parts) > 1:
                # Labelled, because a bare name is deliberately not detected:
                # the joined value must carry the label the component already
                # supplied, or the probe finds nothing at all.
                joined = "".join(parts)
                for _text, path in holders:
                    extra[path] = joined
            else:
                # One component may still carry a whole name. A resource that
                # writes only a surname still identifies someone, and
                # ``name.text`` holds a complete name in one string. The value
                # is offered as its own completion, which is what makes it a
                # labelled probe at all: ``text`` is also the narrative key
                # elsewhere in FHIR, so it cannot be given a global label.
                for key in _NAME_VALUE_KEYS:
                    value = node.get(key)
                    if isinstance(value, str) and value.strip():
                        extra[f"{pointer}/{_escape(key)}"] = value
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    stack.append((value, f"{pointer}/{_escape(key)}"))
        elif isinstance(node, list):
            for index in range(len(node) - 1, -1, -1):
                stack.append((node[index], f"{pointer}/{index}"))
    return extra


def parse_fhir_payload(document: Any):
    """Build a structured payload from a decoded FHIR document.

    The traversal is the shared JSON one, so FHIR gets the same leaf
    normalisation, the same control-character refusal and the same read-only
    numeric leaves as any other structured payload. What FHIR adds is the
    HumanName probe above: the components are also offered joined, because a
    name split across them is invisible to every detector otherwise.
    """
    payload = from_document(document)
    completion = _complete_names(document)
    if not completion:
        return payload
    leaves = tuple(
        replace(
            leaf,
            completed=completion[leaf.path],
            probes=leaf.probes or ("姓名",),
        )
        if leaf.path in completion
        else leaf
        for leaf in payload.leaves
    )
    return replace(payload, leaves=leaves)
