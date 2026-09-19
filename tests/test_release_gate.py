"""Release-gate integration, adversarial and cross-interface tests."""

import json

from cli.main import EXIT_ERROR, EXIT_OK, main
from core.errors import AuditError
from core.model import ReasonCode, Verdict
from medical_privacy_guard import Guard

DEMO = """患者：测试患者甲
电话：13800000000
住院号：SYNTH-MRN-0001
就诊日期：2026-08-21
诊断：Crohn disease
当前使用 infliximab 治疗。
"""


def test_official_demo_sanitizes_and_verifies():
    result = Guard().sanitize(DEMO, "external_approved", "EXTERNAL_AI_ASSISTANCE")
    assert result.decision_before.verdict is Verdict.SANITIZE
    assert result.verification is not None and result.verification.passed
    assert result.decision_after is not None
    assert result.decision_after.verdict is Verdict.ALLOW
    output = result.sanitized_payload.content
    for raw in ("测试患者甲", "13800000000", "SYNTH-MRN-0001", "2026-08-21"):
        assert raw not in output
    assert "Crohn disease" in output
    assert "infliximab" in output


def test_long_names_and_mrn_leave_no_suffix_after_verification():
    text = "Patient: John Michael Smith, MRN: SYNTH-MRN-0001"
    result = Guard().sanitize(text, "external_unknown", "EXTERNAL_AI_ASSISTANCE")
    assert result.verification is not None and result.verification.passed
    output = result.sanitized_payload.content
    assert "John" not in output
    assert "Smith" not in output
    assert "SYNTH-MRN-0001" not in output
    assert not output.endswith("01")


def test_network_and_address_identifiers_are_transformed():
    text = (
        "地址：北京市朝阳区建国路88号；"
        "影像 https://hospital.example/patient/123；服务器 10.0.0.8"
    )
    result = Guard().sanitize(text, "external_unknown", "EXTERNAL_AI_ASSISTANCE")
    assert result.verification is not None and result.verification.passed
    output = result.sanitized_payload.content
    assert "建国路88号" not in output
    assert "hospital.example" not in output
    assert "10.0.0.8" not in output


def test_medical_content_to_unknown_external_recipient_asks():
    result = Guard().evaluate(
        "诊断：HIV感染；当前用药多替拉韦",
        "external_unknown",
        "EXTERNAL_AI_ASSISTANCE",
    )
    assert result.decision.verdict is Verdict.ASK
    assert ReasonCode.MEDICAL_CONTENT_PRESENT in result.decision.reason_codes
    assert ReasonCode.UNKNOWN_RECIPIENT in result.decision.reason_codes
    assert ReasonCode.CONSENT_REQUIRED in result.decision.reason_codes


def test_unknown_purpose_has_real_ask_path():
    result = Guard().evaluate("电话13800000000", "external_unknown", "UNKNOWN")
    assert result.decision.verdict is Verdict.ASK
    assert ReasonCode.PURPOSE_NOT_DECLARED in result.decision.reason_codes


def test_cli_and_api_decisions_conform(tmp_path, capsys):
    source = tmp_path / "note.txt"
    source.write_text("电话13800000000", encoding="utf-8")
    api = Guard().evaluate(
        source.read_text(encoding="utf-8"),
        "external_unknown",
        "EXTERNAL_AI_ASSISTANCE",
    )
    rc = main(["inspect", "--json", str(source)])
    cli = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert cli["decision"] == api.decision.verdict.value
    assert cli["reason_codes"] == [r.value for r in api.decision.reason_codes]


def test_cli_audit_failure_releases_no_output(tmp_path, capsys, monkeypatch):
    source = tmp_path / "note.txt"
    output = tmp_path / "released.txt"
    source.write_text("电话13800000000", encoding="utf-8")

    def fail_record(self, event):
        raise AuditError("synthetic audit failure")

    monkeypatch.setattr("medical_privacy_guard.guard.AuditWriter.record", fail_record)
    rc = main([
        "sanitize",
        "--audit-dir",
        str(tmp_path / "audit"),
        "-o",
        str(output),
        str(source),
    ])
    captured = capsys.readouterr()
    assert rc == EXIT_ERROR
    assert not output.exists()
    assert captured.out == ""
    assert "audit failure" in captured.err


# -- the release path on a full clinical note -------------------------------
#
# Every other test here sanitizes a payload with no clinical content, which is
# a shape no real note has. A note that mentions history, sex and an age
# exercises a different branch of verification, and that branch was broken:
# nothing was ever released, and the benchmark reported zero residual PHI
# because it never had a payload to inspect.

NOTE = """患者：测试患者甲，性别：男，年龄：67岁
联系地址：北京市朝阳区建国路88号院2号楼
住院号：SYNTH-MRN-0001
就诊日期：2026-08-21
主诉：突发右侧肢体无力3小时。
既往史：高血压病史10年。
诊断：脑梗死
"""

RAW_VALUES = (
    "测试患者甲",
    "67岁",
    "建国路88号院2号楼",
    "SYNTH-MRN-0001",
    "2026-08-21",
)


def test_clinical_note_is_released_and_verified():
    result = Guard().sanitize(NOTE, "external_approved", "EXTERNAL_AI_ASSISTANCE")
    assert result.decision_before.verdict is Verdict.SANITIZE
    assert result.verification is not None and result.verification.passed
    assert result.sanitized_payload is not None, "a verified note must be released"
    output = result.sanitized_payload.content
    for raw in RAW_VALUES:
        assert raw not in output, raw


def test_clinical_note_output_converges_to_allow():
    """Re-running policy on the released note must not still demand work.

    If it does, the guard is telling itself the output is unsafe, which is how
    the release path silently produced nothing.
    """
    result = Guard().sanitize(NOTE, "external_approved", "EXTERNAL_AI_ASSISTANCE")
    assert result.decision_after is not None
    assert result.decision_after.verdict is Verdict.ALLOW


def test_clinical_note_keeps_clinical_meaning():
    """De-identification must not strip the clinical content itself."""
    output = Guard().sanitize(
        NOTE, "external_approved", "EXTERNAL_AI_ASSISTANCE"
    ).sanitized_payload.content
    for kept in ("脑梗死", "高血压", "突发右侧肢体无力"):
        assert kept in output, kept


def test_clinical_note_generalizes_rather_than_erases_age():
    output = Guard().sanitize(
        NOTE, "external_approved", "EXTERNAL_AI_ASSISTANCE"
    ).sanitized_payload.content
    assert "60-69岁" in output


def test_clinical_note_to_unknown_recipient_never_releases():
    """Medical content to an unknown endpoint needs consent, so nothing ships."""
    result = Guard().sanitize(NOTE, "external_unknown", "EXTERNAL_AI_ASSISTANCE")
    assert result.decision_before.verdict is Verdict.ASK
    assert result.sanitized_payload is None


def test_date_shift_profile_releases_with_residual_dates():
    """Under DATE_SHIFT a shifted date is still a date, so the policy re-run
    returns SANITIZE rather than ALLOW. The note must still be released."""
    result = Guard(profile="research").sanitize(
        NOTE, "external_approved", "EXTERNAL_AI_ASSISTANCE"
    )
    assert result.decision_before.verdict is Verdict.SANITIZE
    assert result.verification is not None and result.verification.passed
    assert result.sanitized_payload is not None
    output = result.sanitized_payload.content
    assert "2026-08-21" not in output
    for raw in ("测试患者甲", "67岁", "SYNTH-MRN-0001"):
        assert raw not in output, raw
