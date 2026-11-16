"""Exercise local approvals and datasets from an isolated installed wheel.

Run with the installed interpreter's -I flag, outside the source directory.
All records, keys and upstream responses are synthetic and temporary.
"""

from __future__ import annotations

import io
import json
import os
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path

import medical_privacy_guard
import medical_privacy_guard.adapters.mcp_gateway
import medical_privacy_guard.core.dataset
import medical_privacy_guard.core.grant_files
from medical_privacy_guard.adapters.mcp_gateway import GatewaySettings, McpGateway
from medical_privacy_guard.core.dataset import analyze_dataset, sanitize_dataset
from medical_privacy_guard.core.grant import GRANT_KEY_ENV, ApprovalRequest, Grant
from medical_privacy_guard.core.grant_files import write_approval_file
from medical_privacy_guard.core.model import Payload

_SERVER = """import json,sys
for line in sys.stdin:
    message=json.loads(line)
    print(json.dumps({'jsonrpc':'2.0','id':message['id'],
                      'result':{'arguments':message['params']['arguments']}}), flush=True)
"""


def _cli(*arguments: str | Path) -> subprocess.CompletedProcess:
    return subprocess.run(  # nosec B603
        [sys.executable, "-I", "-B", "-m", "medical_privacy_guard.cli.main", *map(str, arguments)],
        capture_output=True, text=True,
    )


def _gateway(message: dict, settings: GatewaySettings) -> dict:
    output = io.BytesIO()
    instance = McpGateway(
        [sys.executable, "-I", "-c", _SERVER], settings,
        stdin=io.BytesIO((json.dumps(message) + "\n").encode()), stdout=output,
    )
    assert instance.run() == 0
    return json.loads(output.getvalue())


def main() -> None:
    for module in (medical_privacy_guard, medical_privacy_guard.core.dataset,
                   medical_privacy_guard.core.grant_files, medical_privacy_guard.adapters.mcp_gateway):
        assert Path(module.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    key = "synthetic-installed-workflow-key"
    os.environ[GRANT_KEY_ENV] = key
    os.environ.pop("MEDICAL_PRIVACY_GUARD_AUDIT_KEY", None)
    os.environ.pop("PYTHONPATH", None)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

    with tempfile.TemporaryDirectory(prefix="mpg-installed-workflow-") as folder:
        root = Path(folder)
        database = root / "grants.sqlite3"
        assert _cli("grant-db-init", "--grant-db", database).returncode == 0
        source = root / "synthetic.json"
        source.write_text(json.dumps({"name": "测试患者甲", "phone": 13800000000}))
        request, grant = root / "request.json", root / "grant.json"
        context = ["--recipient", "external_approved", "--purpose", "research"]
        assert _cli("sanitize", source, *context, "--approval-request-out", request).returncode == 3
        issued = _cli("grant-issue", request, "--approve", "--issuer", "synthetic-installed",
                      "--ttl-seconds", "300", "--accepted-type", "PHONE", "--output", grant)
        assert issued.returncode == 0 and key not in issued.stdout + issued.stderr
        released = _cli("sanitize", source, *context, "--grant-file", grant, "--grant-db", database)
        assert released.returncode == 0 and json.loads(released.stdout)["name"] != "测试患者甲"
        assert _cli("sanitize", source, *context, "--grant-file", grant,
                    "--grant-db", database).returncode == 3
        parsed = Grant.from_json(grant.read_text())
        assert _cli("grant-revoke", parsed.grant_id, "--grant-db", database).returncode == 0
        assert _cli("sanitize", source, *context, "--grant-file", grant,
                    "--grant-db", database).returncode == 3

        message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "synthetic-tool", "arguments": {"name": "测试患者甲", "phone": 13800000000},
        }}
        settings = GatewaySettings(recipient="external_approved", purpose="research",
                                   approval_scope="synthetic-installed-server",
                                   grant_database=str(database))
        refused = _gateway(message, settings)
        metadata = refused["error"]["data"]["approval_requests"][0]["request"]
        mcp_request, mcp_grant = root / "mcp-request.json", root / "mcp-grant.json"
        write_approval_file(mcp_request, ApprovalRequest.from_json(json.dumps(metadata)))
        assert _cli("grant-issue", mcp_request, "--approve", "--issuer", "synthetic-installed",
                    "--ttl-seconds", "300", "--accepted-type", "PHONE",
                    "--output", mcp_grant).returncode == 0
        settings = GatewaySettings(recipient="external_approved", purpose="research",
                                   approval_scope="synthetic-installed-server",
                                   grant_database=str(database), grant_files=(str(mcp_grant),))
        accepted = _gateway(message, settings)
        assert accepted["result"]["arguments"]["name"] != "测试患者甲"
        assert "error" in _gateway(message, settings)

        result = sanitize_dataset([Payload(kind="json", content={"name": "张三"}),
                                   Payload(kind="csv", content="name\n张三\n")],
                                  "external_approved", "RESEARCH")
        token = json.loads(result.results[0].sanitized_payload.content)["name"]
        assert token in result.results[1].sanitized_payload.content
        report = analyze_dataset([{"age": 40}, {"age": "40"}, {"age": 50}], ["age"]).to_dict()
        assert report["row_count"] == 3 and report["singleton_rows"] == 1
        data = root / "rows.csv"
        data.write_text("age\n40\n40\n50\n")
        report_cli = _cli("dataset-risk", data, "--quasi-identifier", "age")
        assert report_cli.returncode == 0 and json.loads(report_cli.stdout)["singleton_rows"] == 1
        minimized = _cli("dataset-sanitize", source, *context, "--output-dir", root / "minimized")
        assert minimized.returncode == 3
        assert not (root / "minimized/001.json").exists()
    print("Installed CLI approvals, MCP scopes, replay/revocation and datasets: PASS")


if __name__ == "__main__":
    main()
