"""Synthetic key retirement and isolated state switching; no live deployment changes."""

import json
import os
import subprocess
import sys

from cli.main import EXIT_ASK, EXIT_ERROR, EXIT_OK
from core.grant import GRANT_KEY_ENV, Grant
from core.grant_sqlite import SqliteGrantRegistry
from core.model import Payload, Purpose, Recipient, TrustLevel
from medical_privacy_guard import Guard

OLD_KEY = "synthetic-retired-cutover-key"
NEW_KEY = "synthetic-active-cutover-key"
DOCUMENT = {"name": "测试患者甲", "phone": 13800000000}
CONTEXT = ["--recipient", "external_approved", "--purpose", "research"]


def _cli(key, *arguments):
    return subprocess.run(
        [sys.executable, "-B", "-m", "cli.main", *map(str, arguments)],
        capture_output=True, text=True, check=False,
        env={**os.environ, GRANT_KEY_ENV: key, "PYTHONDONTWRITEBYTECODE": "1"},
    )


def _issue(key, request, grant, uses=1):
    return _cli(key, "grant-issue", request, "--approve", "--issuer", "synthetic-cutover-reviewer",
                "--ttl-seconds", "300", "--uses-allowed", str(uses), "--accepted-type", "PHONE",
                "--output", grant)


def test_retired_credentials_cannot_enter_new_shared_state(tmp_path):
    source = tmp_path / "synthetic.json"
    source.write_text(json.dumps(DOCUMENT))
    old_request, old_file = tmp_path / "old-request.json", tmp_path / "old-grant.json"
    exported = _cli(OLD_KEY, "sanitize", source, *CONTEXT, "--approval-request-out", old_request)
    assert exported.returncode == EXIT_ASK
    assert _issue(OLD_KEY, old_request, old_file).returncode == EXIT_OK
    old_grant = Grant.from_json(old_file.read_text())
    legacy = Guard(grant_key=OLD_KEY.encode())
    recipient = Recipient(kind="cli", trust_level=TrustLevel.EXTERNAL_APPROVED)
    original_payload = Payload(kind="json", content=source.read_text())
    assert legacy.sanitize(original_payload, recipient, Purpose.RESEARCH,
                           grant=old_grant).sanitized_payload is not None
    assert legacy.sanitize(original_payload, recipient, Purpose.RESEARCH,
                           grant=old_grant).sanitized_payload is None

    database = tmp_path / "new-shared.sqlite3"
    assert _cli(NEW_KEY, "grant-db-init", "--grant-db", database).returncode == EXIT_OK
    failed = _cli(NEW_KEY, "sanitize", source, *CONTEXT, "--grant-file", old_file,
                  "--grant-db", database)
    assert failed.returncode == EXIT_ASK and not failed.stdout
    registry = SqliteGrantRegistry(database)
    assert registry.remaining(old_grant.grant_id) == 0
    assert _issue(NEW_KEY, old_request, tmp_path / "unsafe-reissue.json").returncode == EXIT_ERROR

    request, grant_file = tmp_path / "new-request.json", tmp_path / "new-grant.json"
    assert _cli(NEW_KEY, "sanitize", source, *CONTEXT,
                "--approval-request-out", request).returncode == EXIT_ASK
    assert _issue(NEW_KEY, request, grant_file, uses=3).returncode == EXIT_OK
    grant = Grant.from_json(grant_file.read_text())
    first = _cli(NEW_KEY, "sanitize", source, *CONTEXT, "--grant-file", grant_file,
                 "--grant-db", database)
    assert first.returncode == EXIT_OK
    assert json.loads(first.stdout)["name"] != DOCUMENT["name"]
    assert registry.remaining(grant.grant_id) == 1
    assert _cli(NEW_KEY, "grant-revoke", grant.grant_id, "--grant-db", database).returncode == EXIT_OK
    for _ in range(2):
        restarted = _cli(NEW_KEY, "sanitize", source, *CONTEXT, "--grant-file", grant_file,
                         "--grant-db", database)
        assert restarted.returncode == EXIT_ASK and not restarted.stdout
        assert "revoked" in restarted.stderr
    assert registry.remaining(grant.grant_id) == 1
    for output in (first.stdout, failed.stderr):
        assert OLD_KEY not in output and NEW_KEY not in output
