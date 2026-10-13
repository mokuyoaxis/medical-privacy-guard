"""Local human approval files and real CLI processes sharing persistent state."""

import json
import os
import subprocess
import sys
from dataclasses import replace

import pytest

from cli.main import EXIT_ASK, EXIT_BLOCK, EXIT_ERROR, EXIT_OK, main
from core.errors import GrantError
from core.grant import GRANT_KEY_ENV, ApprovalRequest, Grant
from core.grant_files import read_approval_file, write_approval_file
from core.grant_sqlite import SqliteGrantRegistry, initialize_grant_registry
from core.model import Payload, Purpose
from medical_privacy_guard import Guard

KEY = "synthetic-local-approval-key"
DOCUMENT = {"name": "测试患者甲", "phone": 13800000000, "mobile": "13900000000"}
COMMON = ["--recipient", "external_approved", "--purpose", "research"]


@pytest.fixture
def workflow(tmp_path, monkeypatch):
    monkeypatch.setenv(GRANT_KEY_ENV, KEY)
    source = tmp_path / "synthetic.json"
    source.write_text(json.dumps(DOCUMENT, ensure_ascii=False))
    request, grant, database = (tmp_path / name for name in ("request.json", "grant.json", "grants.sqlite3"))
    initialize_grant_registry(database)
    return source, request, grant, database


def _export(workflow):
    source, request, _, _ = workflow
    return main(["sanitize", str(source), *COMMON, "--approval-request-out", str(request)])


def _issue(workflow, *, approve=True, output=None):
    _, request, grant, _ = workflow
    arguments = ["grant-issue", str(request), "--issuer", "synthetic-reviewer",
                 "--ttl-seconds", "300", "--accepted-type", "PHONE", "-o", str(output or grant)]
    return main(arguments + (["--approve"] if approve else []))


def _run_source(workflow, *extra):
    source, _, grant, database = workflow
    return main(["sanitize", str(source), *COMMON, "--grant-file", str(grant),
                 "--grant-db", str(database), *extra])


@pytest.mark.parametrize("payload", [
    Payload(kind="text", content="本例为罕见变异型病例"),
    Payload(kind="json", content=DOCUMENT),
    Payload(kind="csv", content="note\n本例为罕见变异型病例\n"),
    Payload(kind="fhir", content={"resourceType": "Condition", "note": [{"text": "本例为罕见变异型病例"}]}),
])
def test_read_only_evaluation_prepares_the_same_signed_disclosure(payload):
    guard = Guard(grant_key=KEY.encode())
    evaluated = guard.evaluate(payload, "external_approved", Purpose.RESEARCH)
    sanitized = guard.sanitize(payload, "external_approved", Purpose.RESEARCH)
    request = evaluated.approval_request
    assert request is not None and request.signature_is_valid(KEY.encode())
    assert request.fingerprint == sanitized.approval_request.fingerprint
    parsed = ApprovalRequest.from_json(request.to_json())
    assert parsed == request and parsed.signature_is_valid(KEY.encode())


def test_non_ask_evaluation_has_no_approval_request():
    assert Guard(grant_key=KEY.encode()).evaluate("普通随访", "local", "RESEARCH").approval_request is None


def test_complete_local_workflow_and_committed_state(workflow, capsys):
    source, request, grant_file, database = workflow
    assert _export(workflow) == EXIT_ASK
    assert "ASK" in capsys.readouterr().err
    request_blob = request.read_text()
    for value in map(str, DOCUMENT.values()):
        assert value not in request_blob
    assert request.stat().st_mode & 0o777 == 0o600
    assert _issue(workflow) == EXIT_OK
    summary = capsys.readouterr()
    assert KEY not in summary.out + summary.err
    grant = Grant.from_json(grant_file.read_text())
    assert grant.signature not in summary.out + summary.err
    assert grant_file.stat().st_mode & 0o777 == 0o600
    output = source.parent / "minimized.json"
    assert _run_source(workflow, "-o", str(output)) == EXIT_OK
    data = json.loads(output.read_text())
    assert data["phone"] == DOCUMENT["phone"]
    assert data["name"] != DOCUMENT["name"] and data["mobile"] != DOCUMENT["mobile"]
    assert SqliteGrantRegistry(database).remaining(grant.grant_id) == 1
    capsys.readouterr()
    assert _run_source(workflow) == EXIT_ASK
    refused = capsys.readouterr()
    assert not refused.out and "already been used" in refused.err


def test_inspect_can_export_without_consuming_or_releasing(workflow, capsys):
    source, request, _, database = workflow
    assert main(["inspect", str(source), *COMMON, "--json", "--approval-request-out", str(request)]) == EXIT_ASK
    visible = capsys.readouterr().out
    for value in map(str, DOCUMENT.values()):
        assert value not in visible
    assert ApprovalRequest.from_json(request.read_text()).signature_is_valid(KEY.encode())
    with SqliteGrantRegistry(database)._connection() as connection:
        assert connection.execute("SELECT count(*) FROM grant_uses").fetchone()[0] == 0


def test_issuance_requires_explicit_confirmation(workflow, capsys):
    assert _export(workflow) == EXIT_ASK
    capsys.readouterr()
    assert _issue(workflow, approve=False) == EXIT_ERROR
    assert not workflow[2].exists()
    assert "--approve" in capsys.readouterr().err


@pytest.mark.parametrize("field, value", [("risk_score", 0), ("fact_counts", {}), ("signature", "invalid")])
def test_tampered_review_metadata_cannot_be_signed(workflow, capsys, field, value):
    assert _export(workflow) == EXIT_ASK
    data = json.loads(workflow[1].read_text())
    data[field] = value
    workflow[1].write_text(json.dumps(data))
    capsys.readouterr()
    assert _issue(workflow) == EXIT_ERROR
    assert not workflow[2].exists()
    assert "signature" in capsys.readouterr().err


def test_missing_active_key_cannot_export_or_issue(workflow, monkeypatch, capsys):
    assert _export(workflow) == EXIT_ASK
    monkeypatch.delenv(GRANT_KEY_ENV)
    capsys.readouterr()
    assert _issue(workflow) == EXIT_ERROR
    assert not workflow[2].exists()


def test_export_and_issuance_never_overwrite_existing_files(workflow, capsys):
    assert _export(workflow) == EXIT_ASK
    original = workflow[1].read_bytes()
    assert _export(workflow) == EXIT_ERROR
    assert workflow[1].read_bytes() == original
    assert _issue(workflow) == EXIT_OK
    original = workflow[2].read_bytes()
    assert _issue(workflow) == EXIT_ERROR
    assert workflow[2].read_bytes() == original


def test_credential_alias_cannot_be_used_as_the_output(workflow, capsys):
    assert _export(workflow) == EXIT_ASK
    assert _issue(workflow) == EXIT_OK
    original = workflow[2].read_bytes()
    assert _run_source(workflow, "-o", str(workflow[2])) == EXIT_ERROR
    assert workflow[2].read_bytes() == original
    grant = Grant.from_json(original)
    assert SqliteGrantRegistry(workflow[3]).remaining(grant.grant_id) == 0


@pytest.mark.parametrize("kind", ["permissions", "symlink", "fifo"])
def test_approval_reader_rejects_unsafe_file_shapes_promptly(tmp_path, kind):
    path = tmp_path / "approval.json"
    if kind == "fifo":
        os.mkfifo(path, 0o600)
    else:
        path.write_text("{}")
        if kind == "symlink":
            link = tmp_path / "link"
            link.symlink_to(path)
            path = link
    with pytest.raises(GrantError):
        read_approval_file(path)


@pytest.mark.parametrize("field, value", [("uses_allowed", True), ("issuer", "\ud800")])
def test_malformed_grant_fields_fail_without_disclosing_values(workflow, field, value, capsys):
    assert _export(workflow) == EXIT_ASK
    assert _issue(workflow) == EXIT_OK
    data = json.loads(workflow[2].read_text())
    data[field] = value
    workflow[2].write_text(json.dumps(data))
    capsys.readouterr()
    assert _run_source(workflow) == EXIT_ERROR
    visible = capsys.readouterr()
    assert not visible.out and KEY not in visible.err


def test_verification_failure_after_approval_still_withholds_and_spends(workflow, monkeypatch, capsys):
    assert _export(workflow) == EXIT_ASK
    assert _issue(workflow) == EXIT_OK
    monkeypatch.setattr("transformers.text.TextTransformer.apply", lambda self, fact, op, tokens: fact.value)
    capsys.readouterr()
    assert _run_source(workflow) == EXIT_BLOCK
    assert not capsys.readouterr().out
    grant = Grant.from_json(workflow[2].read_text())
    assert SqliteGrantRegistry(workflow[3]).remaining(grant.grant_id) == 1


def test_registry_commands_and_a_restarted_cli_share_revocation(workflow, capsys):
    assert _export(workflow) == EXIT_ASK
    assert _issue(workflow) == EXIT_OK
    grant = Grant.from_json(workflow[2].read_text())
    database = str(workflow[3])
    capsys.readouterr()
    assert main(["grant-status", grant.grant_id, "--grant-db", database]) == EXIT_OK
    assert json.loads(capsys.readouterr().out) == {"uses_consumed": 0, "revoked": False}
    assert main(["grant-revoke", grant.grant_id, "--grant-db", database]) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["revoked"]
    run = subprocess.run(
        [sys.executable, "-B", "-m", "cli.main", "sanitize", str(workflow[0]), *COMMON,
         "--grant-file", str(workflow[2]), "--grant-db", database],
        capture_output=True, text=True,
        env={**os.environ, GRANT_KEY_ENV: KEY, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert run.returncode == EXIT_ASK and not run.stdout
    assert "revoked" in run.stderr and KEY not in run.stderr


def test_registry_init_refuses_existing_state(tmp_path, capsys):
    path = tmp_path / "grants.sqlite3"
    assert main(["grant-db-init", "--grant-db", str(path)]) == EXIT_OK
    original = path.read_bytes()
    assert main(["grant-db-init", "--grant-db", str(path)]) == EXIT_ERROR
    assert path.read_bytes() == original


def test_signature_covers_review_metadata_but_not_its_serialization():
    request = Guard(grant_key=KEY.encode()).evaluate(
        Payload(kind="json", content=DOCUMENT), "external_approved", "RESEARCH"
    ).approval_request
    data = json.loads(request.to_json())
    parsed = ApprovalRequest.from_json(json.dumps(data, indent=4))
    assert parsed.signature_is_valid(KEY.encode())
    assert not replace(request, risk_level="LOW", risk_score=0).signature_is_valid(KEY.encode())
    assert not replace(request, signature="不合法").signature_is_valid(KEY.encode())


def test_partial_approval_output_is_preserved_on_sync_failure(tmp_path, monkeypatch):
    request = Guard(grant_key=KEY.encode()).evaluate(
        Payload(kind="json", content=DOCUMENT), "external_approved", "RESEARCH"
    ).approval_request
    path = tmp_path / "request.json"

    def fail_sync(descriptor):
        raise OSError("synthetic synchronization failure")

    monkeypatch.setattr(os, "fsync", fail_sync)
    with pytest.raises(GrantError):
        write_approval_file(path, request)
    assert path.exists() and path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("ttl", [10**12, 10**20])
def test_issuance_rejects_unrepresentable_expiry_without_creating_a_grant(workflow, ttl, capsys):
    assert _export(workflow) == EXIT_ASK
    capsys.readouterr()
    assert main(["grant-issue", str(workflow[1]), "--approve", "--issuer", "synthetic-reviewer",
                 "--ttl-seconds", str(ttl), "-o", str(workflow[2])]) == EXIT_ERROR
    assert not workflow[2].exists() and not capsys.readouterr().out
