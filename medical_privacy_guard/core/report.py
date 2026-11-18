"""One-shot static HTML report over audit and grant metadata.

The report is a local, self-contained page: inline styles, no scripts, no
external requests. It renders aggregates only. Audit events are metadata by
design (see :mod:`medical_privacy_guard.core.audit`) and the grant registry
stores hashed grant keys, so nothing in this module can surface clinical
text, detector values or a raw grant ID — those never reach its inputs.

Sections whose source was not supplied are omitted entirely; the header
states exactly which sources the page was built from.
"""

from __future__ import annotations

import html
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Sequence

from .audit import AuditEvent, ChainVerification
from .grant import _now, _parse_iso

#: Verdicts and risk levels render in this fixed order; anything unexpected
#: follows alphabetically so a future level never silently disappears.
_VERDICT_ORDER = ("ALLOW", "SANITIZE", "ASK", "BLOCK")
_RISK_ORDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

#: How many rows the per-grant table shows before it truncates with a note.
_MAX_GRANT_ROWS = 200
#: How many entries the "top" counters (entities, reasons, transformations)
#: show; the remainder is folded into the section note.
_TOP_N = 12


@dataclass(frozen=True)
class AuditSummary:
    """Aggregates over a sequence of audit events."""

    total: int
    first_timestamp: str
    last_timestamp: str
    decisions: Counter[str]
    risk_levels: Counter[str]
    entity_types: Counter[str]
    reason_codes: Counter[str]
    recipients: Counter[str]
    purposes: Counter[str]
    transformations: Counter[str]
    verifications: Counter[str]
    grant_assisted: int
    grant_ids: int
    grant_issuers: Counter[str]
    dictionary_events: int


@dataclass(frozen=True)
class GrantRow:
    """One registry row, keyed by the stored hash of the grant ID."""

    grant_key: str
    uses_allowed: int
    uses_consumed: int
    expires_at: str
    revoked: bool

    def status(self, now: datetime) -> str:
        if self.revoked:
            return "revoked"
        if _parse_iso(self.expires_at) <= now:
            return "expired"
        if self.uses_consumed >= self.uses_allowed:
            return "exhausted"
        return "active"


@dataclass(frozen=True)
class GrantSummary:
    """Aggregates over a grant registry snapshot."""

    rows: tuple[GrantRow, ...]
    revoked_only: int
    active: int
    expired: int
    exhausted: int
    revoked: int
    uses_consumed: int
    uses_allowed: int

    @property
    def recorded(self) -> int:
        """Grants with at least one committed use record."""
        return len(self.rows)


def summarize_events(events: Sequence[AuditEvent]) -> AuditSummary:
    """Aggregate audit events; only metadata fields are read."""
    entity_types: Counter[str] = Counter()
    for event in events:
        entity_types.update(event.entity_counts)
    timestamps = [event.timestamp for event in events]
    return AuditSummary(
        total=len(events),
        first_timestamp=min(timestamps, default=""),
        last_timestamp=max(timestamps, default=""),
        decisions=Counter(event.decision for event in events),
        risk_levels=Counter(event.risk_level for event in events),
        entity_types=entity_types,
        reason_codes=Counter(
            code for event in events for code in event.reason_codes
        ),
        recipients=Counter(event.recipient_class for event in events),
        purposes=Counter(event.purpose for event in events),
        transformations=Counter(
            label for event in events for label in event.transformations
        ),
        verifications=Counter(event.verification for event in events),
        grant_assisted=sum(1 for event in events if event.grant_id),
        grant_ids=len({event.grant_id for event in events if event.grant_id}),
        grant_issuers=Counter(
            event.grant_issuer for event in events if event.grant_issuer
        ),
        dictionary_events=sum(1 for event in events if event.dictionary_loaded),
    )


def summarize_grants(
    rows: Sequence[tuple[str, int, int, str, bool]],
    revoked_only_keys: Sequence[str] = (),
    *,
    now: datetime | None = None,
) -> GrantSummary:
    """Aggregate registry snapshot rows.

    *rows* are ``(grant_key, uses_allowed, uses_consumed, expires_at,
    revoked)`` as stored; *revoked_only_keys* are revocation tombstones for
    grants that never consumed a use, which carry no budget row.
    """
    moment = now if now is not None else _now()
    grants = tuple(
        GrantRow(
            grant_key=key,
            uses_allowed=allowed,
            uses_consumed=consumed,
            expires_at=expires_at,
            revoked=revoked,
        )
        for key, allowed, consumed, expires_at, revoked in rows
    )
    statuses = Counter(grant.status(moment) for grant in grants)
    return GrantSummary(
        rows=grants,
        revoked_only=len(revoked_only_keys),
        active=statuses["active"],
        expired=statuses["expired"],
        exhausted=statuses["exhausted"],
        revoked=statuses["revoked"] + len(revoked_only_keys),
        uses_consumed=sum(grant.uses_consumed for grant in grants),
        uses_allowed=sum(grant.uses_allowed for grant in grants),
    )


# -- rendering ---------------------------------------------------------------

#: UI languages. Data labels (verdicts, entity types, reason codes) are
#: canonical values from the audit stream and are never translated; only
#: the page's own prose is.
LANGS = ("en", "zh")

_TEXT: dict[str, dict[str, str]] = {
    "en": {
        "html_lang": "en",
        "title": "medical-privacy-guard report",
        "generated": "Generated {stamp} (UTC), locally.",
        "note": (
            "Aggregates only: audit events carry metadata by design, and "
            "the registry stores hashed grant keys — no clinical text, "
            "detector values or raw grant IDs appear in this page."
        ),
        "sources": "Sources",
        "audit_log": "Audit log",
        "chain_intact": "Chain integrity: INTACT",
        "chain_broken": "Chain integrity: BROKEN",
        "verified": "Verified {total} records ({chained} chained, {unchained} pre-chain).",
        "failures": "{count} failure(s):",
        "events_range": "Events from {first} to {last} (UTC).",
        "decisions": "Decisions",
        "risk_levels": "Risk levels",
        "entity_types": "Detected entity types (total mentions)",
        "reason_codes": "Reason codes",
        "transformations": "Transformations applied",
        "recipients_purposes": "Recipients and purposes",
        "verification_outcomes": "Verification outcomes",
        "grant_releases": (
            "Releases under a grant: {events} event(s) across {grants} "
            "grant(s); institution dictionary active in {dictionary} event(s)."
        ),
        "grant_issuers": "Grant issuers",
        "no_records": "No records.",
        "folded": "… and {count} more, folded out of the top list.",
        "grant_registry": "Grant registry",
        "card_recorded": "Recorded grants",
        "card_active": "Active",
        "card_expired": "Expired",
        "card_exhausted": "Exhausted",
        "card_revoked": "Revoked",
        "card_uses": "Uses consumed",
        "revoked_only": (
            "{count} revoked grant(s) never consumed a use and have no "
            "budget row below."
        ),
        "no_grants": "No grant has consumed a use yet.",
        "th_grant": "Grant (key hash, truncated)",
        "th_uses": "Uses",
        "th_expires": "Expires (UTC)",
        "th_status": "Status",
        "status_active": "active",
        "status_expired": "expired",
        "status_exhausted": "exhausted",
        "status_revoked": "revoked",
        "showing_first": "Showing the first {shown} of {total} recorded grants.",
    },
    "zh": {
        "html_lang": "zh-CN",
        "title": "medical-privacy-guard 报告",
        "generated": "生成于 {stamp}（UTC），本地生成。",
        "note": (
            "本页只含聚合数据：审计事件在设计上只承载元数据，登记册中存的"
            "是授权编号的哈希——本页不出现任何病历原文、检测器原文或完整"
            "授权编号。"
        ),
        "sources": "数据来源",
        "audit_log": "审计日志",
        "chain_intact": "哈希链完整性：完整",
        "chain_broken": "哈希链完整性：已断裂",
        "verified": "共核查 {total} 条记录（已上链 {chained} 条，链前 {unchained} 条）。",
        "failures": "{count} 处失败：",
        "events_range": "事件时间范围：{first} 至 {last}（UTC）。",
        "decisions": "裁决分布",
        "risk_levels": "风险等级",
        "entity_types": "检出实体类型（总提及次数）",
        "reason_codes": "原因代码",
        "transformations": "已执行的变换",
        "recipients_purposes": "接收方与用途",
        "verification_outcomes": "二次验证结果",
        "grant_releases": (
            "凭授权放行：{events} 条事件，涉及 {grants} 个授权；"
            "机构词典在 {dictionary} 条事件中启用。"
        ),
        "grant_issuers": "授权签发方",
        "no_records": "无记录。",
        "folded": "……另有 {count} 项，未列入前排。",
        "grant_registry": "授权登记册",
        "card_recorded": "已登记授权",
        "card_active": "有效",
        "card_expired": "已过期",
        "card_exhausted": "已用尽",
        "card_revoked": "已撤销",
        "card_uses": "已用次数",
        "revoked_only": "{count} 个已撤销授权从未使用过，下表无其预算行。",
        "no_grants": "尚无任何授权被使用过。",
        "th_grant": "授权（密钥哈希，截断显示）",
        "th_uses": "次数",
        "th_expires": "到期时间（UTC）",
        "th_status": "状态",
        "status_active": "有效",
        "status_expired": "已过期",
        "status_exhausted": "已用尽",
        "status_revoked": "已撤销",
        "showing_first": "仅显示前 {shown} 个，共 {total} 个已登记授权。",
    },
}

_CSS = """
:root { color-scheme: light dark; }
body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
       margin: 2rem auto; max-width: 880px; padding: 0 1rem; line-height: 1.5; }
h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
h2 { font-size: 1.15rem; margin-top: 2rem; border-bottom: 2px solid #4a6fa5;
     padding-bottom: 0.25rem; }
.meta { color: #666; font-size: 0.9rem; }
table { border-collapse: collapse; width: 100%; margin: 0.75rem 0; }
th, td { text-align: left; padding: 0.3rem 0.6rem; border-bottom: 1px solid #ccc; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.bar-row { display: flex; align-items: center; gap: 0.6rem; margin: 0.2rem 0; }
.bar-label { flex: 0 0 13rem; overflow-wrap: anywhere; }
.bar-track { flex: 1; background: rgba(127, 127, 127, 0.18); height: 0.9rem; }
.bar-fill { height: 100%; background: #4a6fa5; }
.bar-num { flex: 0 0 4rem; text-align: right; font-variant-numeric: tabular-nums; }
.v-ALLOW { background: #2e7d32; } .v-SANITIZE { background: #b58900; }
.v-ASK { background: #e07b39; } .v-BLOCK { background: #c62828; }
.r-LOW { background: #2e7d32; } .r-MEDIUM { background: #b58900; }
.r-HIGH { background: #e07b39; } .r-CRITICAL { background: #c62828; }
.status { font-weight: 700; }
.ok { color: #2e7d32; } .bad { color: #c62828; }
.cards { display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 0.75rem 0; }
.card { border: 1px solid #bbb; border-radius: 0.5rem; padding: 0.6rem 0.9rem;
        min-width: 7.5rem; }
.card .n { font-size: 1.4rem; font-weight: 700; display: block; }
code { font-size: 0.85em; overflow-wrap: anywhere; }
"""


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _ordered(counter: Mapping[str, int], order: Sequence[str]) -> list[str]:
    known = [name for name in order if name in counter]
    rest = sorted(name for name in counter if name not in order)
    return known + rest


def _bar_rows(
    text: Mapping[str, str],
    counter: Mapping[str, int],
    *,
    order: Sequence[str] = (),
    css_prefix: str = "",
    limit: int | None = None,
) -> str:
    if not counter:
        return f'<p class="meta">{_esc(text["no_records"])}</p>'
    names = _ordered(counter, order) if order else [
        name for name, _ in Counter(counter).most_common()
    ]
    shown = names[:limit] if limit else names
    peak = max(counter.values())
    rows = []
    for name in shown:
        value = counter[name]
        width = round(100 * value / peak) if peak else 0
        css = f" {css_prefix}{_esc(name)}" if css_prefix else ""
        rows.append(
            f'<div class="bar-row"><span class="bar-label">{_esc(name)}</span>'
            f'<span class="bar-track"><span class="bar-fill{css}" '
            f'style="display:block;width:{width}%"></span></span>'
            f'<span class="bar-num">{value}</span></div>'
        )
    if limit and len(names) > limit:
        rows.append(
            f'<p class="meta">{_esc(text["folded"].format(count=len(names) - limit))}</p>'
        )
    return "\n".join(rows)


def _audit_section(
    text: Mapping[str, str], summary: AuditSummary, chain: ChainVerification
) -> str:
    parts = [f"<h2>{_esc(text['audit_log'])}</h2>"]
    verified = text["verified"].format(
        total=chain.total, chained=chain.chained, unchained=chain.unchained
    )
    if chain.verified:
        parts.append(
            f'<p class="status ok">{_esc(text["chain_intact"])}</p>'
            f"<p>{_esc(verified)}</p>"
        )
    else:
        parts.append(
            f'<p class="status bad">{_esc(text["chain_broken"])}</p>'
            f"<p>{_esc(verified)} "
            + _esc(text["failures"].format(count=len(chain.failures)))
            + "</p><ul>"
            + "".join(f"<li>{_esc(failure)}</li>" for failure in chain.failures)
            + "</ul>"
        )
    if summary.total:
        parts.append(
            "<p>"
            + _esc(
                text["events_range"].format(
                    first=summary.first_timestamp, last=summary.last_timestamp
                )
            )
            + "</p>"
        )
    parts.append(f"<h3>{_esc(text['decisions'])}</h3>")
    parts.append(
        _bar_rows(text, summary.decisions, order=_VERDICT_ORDER, css_prefix="v-")
    )
    parts.append(f"<h3>{_esc(text['risk_levels'])}</h3>")
    parts.append(
        _bar_rows(text, summary.risk_levels, order=_RISK_ORDER, css_prefix="r-")
    )
    parts.append(f"<h3>{_esc(text['entity_types'])}</h3>")
    parts.append(_bar_rows(text, summary.entity_types, limit=_TOP_N))
    parts.append(f"<h3>{_esc(text['reason_codes'])}</h3>")
    parts.append(_bar_rows(text, summary.reason_codes, limit=_TOP_N))
    parts.append(f"<h3>{_esc(text['transformations'])}</h3>")
    parts.append(_bar_rows(text, summary.transformations, limit=_TOP_N))
    parts.append(f"<h3>{_esc(text['recipients_purposes'])}</h3>")
    parts.append(_bar_rows(text, summary.recipients))
    parts.append(_bar_rows(text, summary.purposes))
    parts.append(f"<h3>{_esc(text['verification_outcomes'])}</h3>")
    parts.append(_bar_rows(text, summary.verifications))
    parts.append(
        "<p>"
        + _esc(
            text["grant_releases"].format(
                events=summary.grant_assisted,
                grants=summary.grant_ids,
                dictionary=summary.dictionary_events,
            )
        )
        + "</p>"
    )
    if summary.grant_issuers:
        parts.append(f"<h3>{_esc(text['grant_issuers'])}</h3>")
        parts.append(_bar_rows(text, summary.grant_issuers))
    return "\n".join(parts)


def _grant_section(
    text: Mapping[str, str], summary: GrantSummary, now: datetime
) -> str:
    parts = [f"<h2>{_esc(text['grant_registry'])}</h2>"]
    cards = [
        (text["card_recorded"], summary.recorded),
        (text["card_active"], summary.active),
        (text["card_expired"], summary.expired),
        (text["card_exhausted"], summary.exhausted),
        (text["card_revoked"], summary.revoked),
        (text["card_uses"], f"{summary.uses_consumed} / {summary.uses_allowed}"),
    ]
    parts.append(
        '<div class="cards">'
        + "".join(
            f'<div class="card"><span class="n">{_esc(value)}</span>'
            f"{_esc(label)}</div>"
            for label, value in cards
        )
        + "</div>"
    )
    if summary.revoked_only:
        parts.append(
            "<p>"
            + _esc(text["revoked_only"].format(count=summary.revoked_only))
            + "</p>"
        )
    if not summary.rows:
        parts.append(f'<p class="meta">{_esc(text["no_grants"])}</p>')
        return "\n".join(parts)
    shown = summary.rows[:_MAX_GRANT_ROWS]
    body = "".join(
        "<tr>"
        f"<td><code>{_esc(row.grant_key[:12])}…</code></td>"
        f'<td class="num">{row.uses_consumed} / {row.uses_allowed}</td>'
        f"<td>{_esc(row.expires_at)}</td>"
        f"<td>{_esc(text['status_' + row.status(now)])}</td>"
        "</tr>"
        for row in shown
    )
    parts.append(
        f"<table><thead><tr><th>{_esc(text['th_grant'])}</th>"
        f'<th class="num">{_esc(text["th_uses"])}</th>'
        f"<th>{_esc(text['th_expires'])}</th><th>{_esc(text['th_status'])}</th>"
        f"</tr></thead><tbody>{body}</tbody></table>"
    )
    if len(summary.rows) > _MAX_GRANT_ROWS:
        parts.append(
            '<p class="meta">'
            + _esc(
                text["showing_first"].format(
                    shown=_MAX_GRANT_ROWS, total=len(summary.rows)
                )
            )
            + "</p>"
        )
    return "\n".join(parts)


def render_html(
    *,
    generated_at: str | None = None,
    sources: Sequence[tuple[str, str]] = (),
    audit: AuditSummary | None = None,
    chain: ChainVerification | None = None,
    grants: GrantSummary | None = None,
    now: datetime | None = None,
    lang: str = "en",
) -> str:
    """Render the full report page from prepared summaries.

    ``audit`` and ``chain`` arrive together or not at all; ``grants`` is
    independent. At least one section must be present. ``lang`` selects the
    page prose (``en`` or ``zh``); data labels stay canonical.
    """
    if lang not in _TEXT:
        raise ValueError(f"unsupported report language: {lang!r}")
    if audit is None and grants is None:
        raise ValueError("a report needs at least one data source")
    text = _TEXT[lang]
    moment = now if now is not None else datetime.now(timezone.utc)
    stamp = generated_at or moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    parts = [
        "<!DOCTYPE html>",
        f'<html lang="{_esc(text["html_lang"])}"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_esc(text['title'])}</title>",
        f"<style>{_CSS}</style></head><body>",
        f"<h1>{_esc(text['title'])}</h1>",
        f'<p class="meta">{_esc(text["generated"].format(stamp=stamp))} '
        f'{_esc(text["note"])}</p>',
    ]
    if sources:
        parts.append(
            f'<p class="meta">{_esc(text["sources"])}: '
            + "; ".join(
                f"{_esc(label)}: <code>{_esc(path)}</code>" for label, path in sources
            )
            + "</p>"
        )
    if audit is not None:
        if chain is None:
            raise ValueError("an audit summary needs its chain verification")
        parts.append(_audit_section(text, audit, chain))
    if grants is not None:
        parts.append(_grant_section(text, grants, moment))
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"
