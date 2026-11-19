"""Deterministic mutation operators for challenge-corpus probes.

The challenge corpus (``tests/fixtures/challenge/``) holds handwritten probes
whose annotations are *type + exact text* pairs, not character offsets. A
mutation therefore has to do its own bookkeeping: whichever value an operator
rewrites, the sidecar's ``must_detect`` text is rewritten in the same step, by
the same code. Nothing here imports from the detectors — operators are written
from real-world form variation, and a mutation that the guard cannot handle is
a finding (it is filed under ``exploratory/``), not a defect to be tuned away.

Workflow enforced by this tool's callers:

1. generate variants into a staging directory (this module's CLI);
2. run the challenge checks against the staging directory;
3. spot-check a sample by hand;
4. file passing probes under ``regression/`` and failing ones under
   ``exploratory/`` with the failure shape recorded in ``probe_note``.

The framework refuses ambiguous seeds (a ``must_detect`` text that does not
occur exactly once), empty mutations, and undeclared verdict changes.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

# ---------------------------------------------------------------------------
# Framework


@dataclass
class Variant:
    """One mutated probe: new text plus its fully-bookkept annotations."""

    text: str
    must_detect: list[dict]
    must_not_detect: list[str]
    note: str
    verdict: str | None = None  # None = keep the seed's expected verdict


@dataclass
class Operator:
    name: str
    operator_class: str  # "format" or "label"
    apply: Callable[[str, dict], list[Variant]]


class MutationRefused(Exception):
    """A seed or variant violated the bookkeeping rails."""


def _seed_rail(text: str, meta: dict) -> None:
    for entry in meta["must_detect"]:
        occurrences = text.count(entry["text"])
        if occurrences != 1:
            raise MutationRefused(
                f"{meta['doc_id']}: must_detect text {entry['text']!r} occurs "
                f"{occurrences} times; bookkeeping would be ambiguous"
            )


def _variant_rail(seed_text: str, seed_meta: dict, variant: Variant) -> None:
    if variant.text == seed_text:
        raise MutationRefused(f"{seed_meta['doc_id']}: empty mutation")
    for entry in variant.must_detect:
        occurrences = variant.text.count(entry["text"])
        if occurrences != 1:
            raise MutationRefused(
                f"{seed_meta['doc_id']}: mutated must_detect text "
                f"{entry['text']!r} occurs {occurrences} times"
            )
    detected_texts = {entry["text"] for entry in variant.must_detect}
    overlap = detected_texts.intersection(variant.must_not_detect)
    if overlap:
        raise MutationRefused(
            f"{seed_meta['doc_id']}: must_not_detect overlaps must_detect: {overlap}"
        )


def generate_variants(text: str, meta: dict, operators: list[Operator]) -> list[tuple[Operator, Variant]]:
    """Apply every operator to one seed probe, enforcing the rails."""
    _seed_rail(text, meta)
    produced: list[tuple[Operator, Variant]] = []
    for operator in operators:
        for variant in operator.apply(text, meta):
            _variant_rail(text, meta, variant)
            produced.append((operator, variant))
    return produced


def mutated_meta(seed_meta: dict, operator: Operator, variant: Variant, doc_id: str) -> dict:
    meta = dict(seed_meta)
    meta["doc_id"] = doc_id
    meta["must_detect"] = variant.must_detect
    meta["must_not_detect"] = variant.must_not_detect
    if variant.verdict is not None:
        meta["expected_verdict"] = variant.verdict
    meta["mutated_from"] = seed_meta["doc_id"]
    meta["operator"] = operator.name
    meta["probe_note"] = (
        f"Mutation of {seed_meta['doc_id']} via {operator.name} "
        f"({operator.operator_class}): {variant.note} "
        f"Seed note: {seed_meta.get('probe_note', '')}"
    )
    return meta


# ---------------------------------------------------------------------------
# Shared helpers


def _replace_value(text: str, meta: dict, old: str, new: str) -> tuple[str, list[dict]]:
    """Rewrite one must_detect value in the text and the annotations."""
    must_detect = []
    for entry in meta["must_detect"]:
        entry = dict(entry)
        if entry["text"] == old:
            entry["text"] = new
        must_detect.append(entry)
    return text.replace(old, new, 1), must_detect


def _values_of_type(meta: dict, *types: str) -> list[str]:
    return [entry["text"] for entry in meta["must_detect"] if entry["type"] in types]


# ---------------------------------------------------------------------------
# Format operators (rewrite a value's surface form)


_FULLWIDTH = {ord(str(i)): ord("０") + i for i in range(10)}
_FULLWIDTH[ord("-")] = ord("－")
_FULLWIDTH[ord(".")] = ord("．")


def _fullwidth(text: str, meta: dict) -> list[Variant]:
    if not any(ch.isascii() and ch.isdigit() for ch in text):
        return []
    new_text = text.translate(_FULLWIDTH)
    must_detect = [
        {**entry, "text": entry["text"].translate(_FULLWIDTH)} for entry in meta["must_detect"]
    ]
    must_not = [item.translate(_FULLWIDTH) for item in meta["must_not_detect"]]
    return [Variant(new_text, must_detect, must_not, "ASCII digits (and - .) written full-width.")]


def _phone_regroup(text: str, meta: dict) -> list[Variant]:
    variants: list[Variant] = []
    for value in _values_of_type(meta, "PHONE"):
        if re.fullmatch(r"1\d{10}", value):
            for grouped in (f"{value[:3]} {value[3:7]} {value[7:]}", f"{value[:3]}-{value[3:7]}-{value[7:]}"):
                new_text, must = _replace_value(text, meta, value, grouped)
                variants.append(Variant(new_text, must, list(meta["must_not_detect"]),
                                        f"Mobile number regrouped as {grouped!r}."))
        elif re.fullmatch(r"1\d{2}[ -]\d{4}[ -]\d{4}", value):
            contiguous = re.sub(r"[ -]", "", value)
            new_text, must = _replace_value(text, meta, value, contiguous)
            variants.append(Variant(new_text, must, list(meta["must_not_detect"]),
                                    "Grouped mobile number written contiguously."))
    return variants


_CN_DIGITS = {"〇": "0", "零": "0", "一": "1", "二": "2", "三": "3", "四": "4",
              "五": "5", "六": "6", "七": "7", "八": "8", "九": "9"}


def _cn_small_number(chars: str) -> int:
    if chars == "十":
        return 10
    if "十" in chars:
        tens, _, ones = chars.partition("十")
        return (int(_CN_DIGITS[tens]) if tens else 1) * 10 + (int(_CN_DIGITS[ones]) if ones else 0)
    return int(_CN_DIGITS[chars])


def _date_restyle(text: str, meta: dict) -> list[Variant]:
    variants: list[Variant] = []
    for value in _values_of_type(meta, "EXACT_DATE"):
        iso = re.fullmatch(r"(\d{4})-(\d{1,2})-(\d{1,2})", value)
        zh = re.fullmatch(r"(\d{4})年(\d{1,2})月(\d{1,2})日", value)
        if iso:
            year, month, day = iso.groups()
            restyled = [f"{year}年{int(month)}月{int(day)}日", f"{year}/{month}/{day}"]
        elif zh:
            year, month, day = zh.groups()
            restyled = [f"{year}-{int(month):02d}-{int(day):02d}", f"{year}/{int(month)}/{int(day)}"]
        elif re.fullmatch(r"[〇零一二三四五六七八九十]+年[一二三四五六七八九十]+月[一二三四五六七八九十]+日", value):
            year_part, rest = value.split("年")
            month_part, day_part = rest.split("月")
            year = "".join(_CN_DIGITS[ch] for ch in year_part)
            restyled = [f"{year}年{_cn_small_number(month_part)}月{_cn_small_number(day_part.rstrip('日'))}日"]
        else:
            continue
        for new_value in restyled:
            new_text, must = _replace_value(text, meta, value, new_value)
            variants.append(Variant(new_text, must, list(meta["must_not_detect"]),
                                    f"Date restyled from {value!r} to {new_value!r}."))
    return variants


def _id_spacing(text: str, meta: dict) -> list[Variant]:
    variants: list[Variant] = []
    for value in _values_of_type(meta, "GOVERNMENT_ID"):
        if re.fullmatch(r"\d{17}[\dXx]", value):
            spaced = f"{value[:6]} {value[6:14]} {value[14:]}"
            new_text, must = _replace_value(text, meta, value, spaced)
            variants.append(Variant(new_text, must, list(meta["must_not_detect"]),
                                    "Resident ID written in 6-8-4 groups separated by spaces."))
    return variants


# ---------------------------------------------------------------------------
# Label operators (rewrite the context around a value)

# Aliases are written from how forms and notes actually vary; nothing here is
# imported from the detectors, so an alias the guard misses is a finding.
_ALIASES = [
    ("联系电话", "电话"),
    ("身份证号码", "身份证"),
    ("身份证号", "身份证号码"),
    ("电子邮箱", "邮箱"),
    ("邮政编码", "邮编"),
    ("出生日期", "出生年月"),
    ("入院日期", "入院时间"),
    ("病历号", "病案号"),
    ("住院号", "住院号码"),
    ("手机号", "手机号码"),
    ("手机", "手机号"),
    ("座机", "固定电话"),
]

_LABELS = [
    "联系电话", "身份证号码", "身份证号", "电子邮箱", "入院日期", "出生日期",
    "邮政编码", "医师签名", "责任护士", "主治医师", "住院号", "病历号",
    "手机号", "座机", "手机", "电话", "邮箱", "姓名", "患者", "家属",
    "床号", "科室", "助手",
]

_SEPARATORS = ["：", ":", "=", " "]


def _label_alias(text: str, meta: dict) -> list[Variant]:
    detected = {entry["text"] for entry in meta["must_detect"]}
    for source, alias in _ALIASES:
        if source in text and source not in detected:
            new_text = text.replace(source, alias, 1)
            return [Variant(new_text, [dict(e) for e in meta["must_detect"]],
                            list(meta["must_not_detect"]),
                            f"Label {source!r} written as its alias {alias!r}.")]
    return []


def _separator_before(text: str, value: str) -> tuple[str, int] | None:
    """Return (separator, value_start) for the separator preceding a value."""
    start = text.find(value)
    if start <= 0:
        return None
    if text[start - 1] in _SEPARATORS:
        return text[start - 1], start
    if text[start - 1] == "（":
        return "（", start
    return "", start


def _separator_swap(text: str, meta: dict) -> list[Variant]:
    variants: list[Variant] = []
    for entry in meta["must_detect"]:
        value = entry["text"]
        found = _separator_before(text, value)
        if found is None:
            continue
        current, start = found
        if current == "" and not any(
            text[:start].endswith(label) for label in _LABELS
        ):
            # No separator and no label: this value is narrative-anchored, and
            # inserting a separator would fabricate a label context that the
            # seed never had — noise, not a variation.
            continue
        if current == "（":
            tail = text.find("）", start)
            if tail < 0:
                continue
            for replacement in ("：", ""):
                new_text = text[: start - 1] + replacement + value + text[tail + 1:]
                variants.append(Variant(new_text, [dict(e) for e in meta["must_detect"]],
                                        list(meta["must_not_detect"]),
                                        f"Bracketed value rewritten with separator {replacement!r}."))
            break
        alternatives = [s for s in _SEPARATORS if s != current] + ([""] if current else [])
        for replacement in alternatives[:3]:
            if current:
                new_text = text[: start - 1] + replacement + text[start:]
            else:
                new_text = text[:start] + replacement + text[start:]
            variants.append(Variant(new_text, [dict(e) for e in meta["must_detect"]],
                                    list(meta["must_not_detect"]),
                                    f"Label/value separator {current!r} swapped for {replacement!r}."))
        break  # one labelled value per variant set keeps bookkeeping auditable
    return variants


_ROLE_TYPES = {"DOCTOR_NAME", "NURSE_NAME", "RELATIVE_NAME"}


def _label_drop(text: str, meta: dict) -> list[Variant]:
    for entry in meta["must_detect"]:
        if entry["type"] in _ROLE_TYPES:
            # A role type is carried by its label; dropping the label changes
            # what the annotation means, not just its surface form.
            continue
        value = entry["text"]
        start = text.find(value)
        head = text[:start]
        for label in _LABELS:
            for sep in ("：", ":", "=", " ", ""):
                if head.endswith(label + sep):
                    new_text = head[: -(len(label) + len(sep))] + text[start:]
                    return [Variant(new_text, [dict(e) for e in meta["must_detect"]],
                                    list(meta["must_not_detect"]),
                                    f"Label {label!r} and its separator dropped; value left in place.")]
    return []


_SPLIT_POINTS = {"PHONE": 3, "GOVERNMENT_ID": 10, "LANDLINE": 8, "MEDICAL_RECORD_NUMBER": 4}


def _value_split_ws(text: str, meta: dict) -> list[Variant]:
    variants: list[Variant] = []
    for entry in meta["must_detect"]:
        point = _SPLIT_POINTS.get(entry["type"])
        value = entry["text"]
        if point is None or not re.fullmatch(r"[\dA-Za-z-]+", value) or len(value) <= point:
            continue
        for filler, label in ((" ", "space"), ("\n", "newline")):
            split_value = value[:point] + filler + value[point:]
            new_text, must = _replace_value(text, meta, value, split_value)
            variants.append(Variant(new_text, must, list(meta["must_not_detect"]),
                                    f"Value split by a {label} after position {point}."))
        break
    return variants


OPERATORS: list[Operator] = [
    Operator("digits_fullwidth", "format", _fullwidth),
    Operator("phone_regroup", "format", _phone_regroup),
    Operator("date_restyle", "format", _date_restyle),
    Operator("id_spacing", "format", _id_spacing),
    Operator("label_alias", "label", _label_alias),
    Operator("separator_swap", "label", _separator_swap),
    Operator("label_drop", "label", _label_drop),
    Operator("value_split_ws", "label", _value_split_ws),
]

OPERATOR_CLASSES = {op.name: op.operator_class for op in OPERATORS}


# ---------------------------------------------------------------------------
# CLI


def _load_probe(sidecar: Path) -> tuple[str, dict]:
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    text = sidecar.with_name(f"{meta['doc_id']}.txt").read_text(encoding="utf-8").rstrip("\n")
    return text, meta


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seeds", type=Path, required=True,
                        help="directory holding seed probes (searched recursively)")
    parser.add_argument("--out", type=Path, required=True,
                        help="staging directory for generated variants")
    parser.add_argument("--operator", action="append", default=[],
                        help="restrict to named operators (repeatable)")
    args = parser.parse_args()

    operators = [op for op in OPERATORS if not args.operator or op.name in args.operator]
    args.out.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    refused: list[str] = []
    for sidecar in sorted(args.seeds.rglob("*.probes.json")):
        text, meta = _load_probe(sidecar)
        try:
            variants = generate_variants(text, meta, operators)
        except MutationRefused as exc:
            refused.append(str(exc))
            continue
        per_operator: dict[str, int] = {}
        for operator, variant in variants:
            per_operator[operator.name] = per_operator.get(operator.name, 0) + 1
            doc_id = f"{meta['doc_id']}__{operator.name}_{per_operator[operator.name]}"
            new_meta = mutated_meta(meta, operator, variant, doc_id)
            (args.out / f"{doc_id}.txt").write_text(variant.text + "\n", encoding="utf-8")
            (args.out / f"{doc_id}.probes.json").write_text(
                json.dumps(new_meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            counts[operator.name] = counts.get(operator.name, 0) + 1
    for name in sorted(counts):
        print(f"{name} ({OPERATOR_CLASSES[name]}): {counts[name]}")
    print(f"total: {sum(counts.values())}")
    for reason in refused:
        print(f"refused: {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
