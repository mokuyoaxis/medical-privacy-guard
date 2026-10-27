"""Trusted local approvals, tool scope and actual upstream disclosure."""

import io
import json
import os
import sys

import pytest

from medical_privacy_guard.adapters.mcp_gateway import GatewayError, GatewaySettings, McpGateway
from medical_privacy_guard.cli.main import main
from medical_privacy_guard.core.grant import GRANT_KEY_ENV, ApprovalRequest, Grant
from medical_privacy_guard.core.grant_files import write_approval_file
from medical_privacy_guard.core.grant_sqlite import SqliteGrantRegistry, initialize_grant_registry
from tests.test_mcp_gateway import _call, by_id, run_gateway, upstream_saw

KEY = "synthetic-mcp-approval-key"
DOCUMENT = {"name": "测试患者甲", "phone": 13800000000, "mobile": "13900000000"}


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    monkeypatch.setenv(GRANT_KEY_ENV, KEY)
    database = tmp_path / "grants.sqlite3"
    initialize_grant_registry(database)
    return tmp_path, database


def _settings(deployment, files=(), *, scope="synthetic-server", requests=None, audit=None):
    return GatewaySettings(
        recipient="external_approved", purpose="research", approval_scope=scope,
        grant_database=str(deployment[1]), grant_files=tuple(map(str, files)),
        approval_request_dir=str(requests) if requests else None,
        audit_dir=str(audit) if audit else None,
    )


def _requests(lines, request_id=1):
    items = by_id(lines)[request_id]["error"]["data"]["approval_requests"]
    return {item["field"]: ApprovalRequest.from_json(json.dumps(item["request"])) for item in items}


def _issue(deployment, request, stem):
    directory = deployment[0]
    source, grant = directory / (stem + "-request.json"), directory / (stem + "-grant.json")
    write_approval_file(source, request)
    assert main(["grant-issue", str(source), "--approve", "--issuer", "synthetic-mcp-reviewer",
                 "--ttl-seconds", "300", "--accepted-type", "PHONE", "-o", str(grant)]) == 0
    return grant


def test_local_approval_releases_minimized_arguments_and_a_restart_cannot_replay(deployment):
    _, before, _ = run_gateway([_call(1, DOCUMENT)], settings=_settings(deployment))
    request = _requests(before)["arguments"]
    assert request.signature_is_valid(KEY.encode())
    for raw in map(str, DOCUMENT.values()):
        assert raw not in json.dumps(before, ensure_ascii=False)
    grant_file = _issue(deployment, request, "arguments")
    settings = _settings(deployment, [grant_file])
    _, released, gateway = run_gateway([_call(2, DOCUMENT)], settings=settings)
    output = upstream_saw(released, 2)["arguments"]
    assert output["phone"] == DOCUMENT["phone"]
    assert output["name"] != DOCUMENT["name"] and output["mobile"] != DOCUMENT["mobile"]
    assert gateway.refused == 0
    _, replay, gateway = run_gateway([_call(3, DOCUMENT)], settings=settings)
    assert "error" in by_id(replay)[3] and gateway.refused == 1
    grant = Grant.from_json(grant_file.read_text())
    assert SqliteGrantRegistry(deployment[1]).remaining(grant.grant_id) == 1
    assert _requests(replay, 3)["arguments"].signature_is_valid(KEY.encode())


@pytest.mark.parametrize("change", ["tool", "server", "field"])
def test_a_grant_cannot_be_moved_to_a_different_tool_server_or_field(deployment, change):
    _, before, _ = run_gateway([_call(1, DOCUMENT)], settings=_settings(deployment))
    grant_file = _issue(deployment, _requests(before)["arguments"], "scope")
    message = _call(2, DOCUMENT)
    scope = "synthetic-server"
    if change == "tool":
        message["params"]["name"] = "other-tool"
    elif change == "server":
        scope = "other-server"
    else:
        message = _call(2, {"note": "普通随访"}, inputResponses=DOCUMENT)
    _, refused, _ = run_gateway([message], settings=_settings(deployment, [grant_file], scope=scope))
    assert "error" in by_id(refused)[2]
    grant = Grant.from_json(grant_file.read_text())
    assert SqliteGrantRegistry(deployment[1]).remaining(grant.grant_id) == 0


def test_client_approval_fields_are_not_authorization(deployment):
    message = _call(1, DOCUMENT, approved=True, grant={"approved": True},
                    _meta={"approval_granted": True})
    _, refused, _ = run_gateway([message], settings=_settings(deployment))
    assert "error" in by_id(refused)[1]


def test_two_sensitive_fields_are_prepared_before_any_grant_is_spent(deployment):
    message = _call(1, DOCUMENT, inputResponses=DOCUMENT)
    _, before, _ = run_gateway([message], settings=_settings(deployment))
    requests = _requests(before)
    assert set(requests) == {"arguments", "inputResponses"}
    assert requests["arguments"].fingerprint != requests["inputResponses"].fingerprint
    first = _issue(deployment, requests["arguments"], "first")
    _, refused, _ = run_gateway([_call(2, DOCUMENT, inputResponses=DOCUMENT)],
                               settings=_settings(deployment, [first]))
    assert "error" in by_id(refused)[2]
    first_grant = Grant.from_json(first.read_text())
    assert SqliteGrantRegistry(deployment[1]).remaining(first_grant.grant_id) == 0
    second = _issue(deployment, requests["inputResponses"], "second")
    _, accepted, _ = run_gateway([_call(3, DOCUMENT, inputResponses=DOCUMENT)],
                                settings=_settings(deployment, [first, second]))
    for field in ("arguments", "inputResponses"):
        assert upstream_saw(accepted, 3)[field]["name"] != DOCUMENT["name"]
    assert SqliteGrantRegistry(deployment[1]).remaining(first_grant.grant_id) == 1


def test_a_configured_missing_file_still_returns_signed_review_requests(deployment):
    path = deployment[0] / "not-created.json"
    _, refused, _ = run_gateway([_call(1, DOCUMENT)], settings=_settings(deployment, [path]))
    assert _requests(refused)["arguments"].signature_is_valid(KEY.encode())
    assert not path.exists()


def test_requests_are_saved_privately_and_no_raw_values_enter_audit(deployment):
    directory, _ = deployment
    requests, audit = directory / "requests", directory / "audit"
    _, refused, _ = run_gateway([_call(1, DOCUMENT)],
                               settings=_settings(deployment, requests=requests, audit=audit))
    request = _requests(refused)["arguments"]
    source = requests / (request.request_id + ".json")
    assert source.is_file() and source.stat().st_mode & 0o777 == 0o600
    assert requests.stat().st_mode & 0o777 == 0o700
    assert ApprovalRequest.from_json(source.read_text()).signature_is_valid(KEY.encode())
    for raw in [KEY, *map(str, DOCUMENT.values())]:
        assert raw not in (audit / "events.jsonl").read_text()


def test_revocation_stops_new_mcp_consumption(deployment):
    _, before, _ = run_gateway([_call(1, DOCUMENT)], settings=_settings(deployment))
    file = _issue(deployment, _requests(before)["arguments"], "revoked")
    grant = Grant.from_json(file.read_text())
    SqliteGrantRegistry(deployment[1]).revoke(grant.grant_id)
    _, refused, _ = run_gateway([_call(2, DOCUMENT)], settings=_settings(deployment, [file]))
    assert "error" in by_id(refused)[2]
    assert SqliteGrantRegistry(deployment[1]).remaining(grant.grant_id) == 0


def test_ambiguous_local_files_cannot_approve_a_call(deployment):
    _, before, _ = run_gateway([_call(1, DOCUMENT)], settings=_settings(deployment))
    request = _requests(before)["arguments"]
    first, second = _issue(deployment, request, "one"), _issue(deployment, request, "two")
    _, refused, _ = run_gateway([_call(2, DOCUMENT)], settings=_settings(deployment, [first, second]))
    assert "error" in by_id(refused)[2]


def test_parent_signing_keys_do_not_enter_the_upstream_environment(deployment, monkeypatch):
    monkeypatch.setenv("MEDICAL_PRIVACY_GUARD_AUDIT_KEY", "synthetic-audit-key")
    monkeypatch.setenv("SYNTHETIC_PROVIDER_TOKEN", "synthetic-provider-token")
    script = """import os,json,sys
print(json.dumps({'grant_key_present': 'MEDICAL_PRIVACY_GUARD_GRANT_KEY' in os.environ,
                  'audit_key_present': 'MEDICAL_PRIVACY_GUARD_AUDIT_KEY' in os.environ,
                  'provider_present': 'SYNTHETIC_PROVIDER_TOKEN' in os.environ}), flush=True)
sys.stdin.read()
"""
    output = io.BytesIO()
    gateway = McpGateway([sys.executable, "-c", script], GatewaySettings(),
                         stdin=io.BytesIO(), stdout=output)
    assert gateway.run() == 0
    assert json.loads(output.getvalue()) == {
        "grant_key_present": False, "audit_key_present": False, "provider_present": True,
    }


def test_approval_configuration_requires_a_unique_deployment_scope(deployment):
    with pytest.raises(GatewayError, match="approval-scope"):
        McpGateway([sys.executable, "-c", "pass"],
                   GatewaySettings(grant_files=(str(deployment[0] / "grant.json"),),
                                   grant_database=str(deployment[1])))


def test_request_export_failure_withholds_and_keeps_the_session_usable(deployment, monkeypatch):
    directory = deployment[0] / "requests"

    def fail_export(*args):
        from medical_privacy_guard.core.errors import GrantError
        raise GrantError("synthetic request write failure")

    monkeypatch.setattr("medical_privacy_guard.adapters.mcp_gateway.write_approval_file", fail_export)
    _, lines, gateway = run_gateway([_call(1, DOCUMENT), _call(2, {"note": "普通随访"})],
                                   settings=_settings(deployment, requests=directory))
    assert "error" in by_id(lines)[1]
    assert "could not be saved" in by_id(lines)[1]["error"]["message"]
    assert "result" in by_id(lines)[2] and gateway.refused == 1


def test_later_field_failure_never_forwards_or_refunds_an_accepted_use(deployment, monkeypatch):
    from medical_privacy_guard.adapters.ingress import sanitize_call
    from medical_privacy_guard.core.errors import ParserError

    _, before, _ = run_gateway([_call(1, DOCUMENT, inputResponses=DOCUMENT)],
                               settings=_settings(deployment))
    requests = _requests(before)
    first = _issue(deployment, requests["arguments"], "first")
    second = _issue(deployment, requests["inputResponses"], "second")

    def fail_second(guard, value, recipient, purpose, *, grant=None):
        if json.loads(recipient.name)[1] == "inputResponses":
            raise ParserError("synthetic second-field failure")
        return sanitize_call(guard, value, recipient, purpose, grant=grant)

    monkeypatch.setattr("medical_privacy_guard.adapters.mcp_gateway.sanitize_call", fail_second)
    _, refused, _ = run_gateway([_call(2, DOCUMENT, inputResponses=DOCUMENT)],
                               settings=_settings(deployment, [first, second]))
    assert "error" in by_id(refused)[2]
    assert not any("result" in message for message in refused)
    registry = SqliteGrantRegistry(deployment[1])
    assert registry.remaining(Grant.from_json(first.read_text()).grant_id) == 1
    assert registry.remaining(Grant.from_json(second.read_text()).grant_id) == 0
    for raw in [KEY, *map(str, DOCUMENT.values())]:
        assert raw not in json.dumps(refused, ensure_ascii=False)


@pytest.mark.parametrize("protected", ["database", "grant"])
@pytest.mark.parametrize("alias", ["hardlink", "symlink"])
def test_audit_alias_is_rejected_before_modifying_approval_state(deployment, protected, alias):
    directory, database = deployment
    files = ()
    path = database
    if protected == "grant":
        from medical_privacy_guard import Guard
        request = Guard(grant_key=KEY.encode()).evaluate(
            DOCUMENT, "external_approved", "RESEARCH",
        ).approval_request
        path = _issue(deployment, request, "protected")
        files = (path,)
    audit = directory / "audit"
    audit.mkdir()
    if alias == "hardlink":
        os.link(path, audit / "events.jsonl")
    else:
        (audit / "events.jsonl").symlink_to(path)
    original, info = path.read_bytes(), path.stat()
    with pytest.raises(GatewayError, match="distinct"):
        McpGateway([sys.executable, "-c", "pass"], _settings(deployment, files, audit=audit))
    assert path.read_bytes() == original
    after = path.stat()
    assert (after.st_mode, after.st_uid, after.st_gid) == (info.st_mode, info.st_uid, info.st_gid)
