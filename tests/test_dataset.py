"""Observable batch tokens and aggregate reports, with no anonymization claims."""

import json
import os

import pytest

from medical_privacy_guard import Guard
from medical_privacy_guard.cli.main import EXIT_ASK, EXIT_ERROR, EXIT_OK, main
from medical_privacy_guard.core.dataset import analyze_dataset, read_dataset_file, sanitize_dataset
from medical_privacy_guard.core.errors import ParserError
from medical_privacy_guard.core.model import Payload
from medical_privacy_guard.transformers import TokenRegistry


def test_combination_counts_are_joint_and_row_weighted():
    rows = [{"age": 40, "town": "SYNTH-A"}] * 3 + [
        {"age": 40, "town": "SYNTH-B"}, {"age": 50, "town": "SYNTH-A"},
    ]
    report = analyze_dataset(rows, ["age", "town"], min_group_size=3).to_dict()
    assert report["row_count"] == 5 and report["group_count"] == 3
    assert (report["smallest_group"], report["largest_group"]) == (1, 3)
    assert report["singleton_rows"] == report["small_group_rows"] == 2
    assert report["singleton_fraction"] == report["small_group_fraction"] == 0.4
    assert report["size_histogram"] == [{"rows_per_group": 1, "groups": 2},
                                        {"rows_per_group": 3, "groups": 1}]
    assert report["engineering_only"] is True
    assert "SYNTH-A" not in json.dumps(report) and "SYNTH-B" not in json.dumps(report)
    assert analyze_dataset(rows, ["age"]).group_count == 2


def test_csv_text_matches_json_scalar_rendering_without_coercing_missing_values():
    rows = [{"value": "40"}, {"value": 40}, {"value": None}, {"value": ""},
            {"value": True}, {"value": "true"}, {"value": "040"}]
    report = analyze_dataset(rows, ["value"])
    assert report.group_count == 5 and report.singleton_rows == 3
    assert report.size_histogram == ((1, 3), (2, 2))


def test_empty_and_exact_threshold_groups_are_not_vacuous_claims():
    empty = analyze_dataset([], ["age"]).to_dict()
    assert empty["row_count"] == empty["smallest_group"] == 0
    assert empty["singleton_fraction"] == 0.0 and empty["engineering_only"]
    exact = analyze_dataset([{"age": 40}] * 3, ["age"], min_group_size=3)
    assert exact.small_group_rows == 0


@pytest.mark.parametrize("rows, columns, threshold", [
    ([{}], ["age"], 2), ([{"age": [40]}], ["age"], 2),
    ([{"age": float("nan")}], ["age"], 2), ([{"age": "\ud800"}], ["age"], 2),
    ([], [], 2), ([], ["age", "age"], 2), ([], ["age"], True), ([], ["age"], 1),
])
def test_invalid_measurement_inputs_fail_explicitly(rows, columns, threshold):
    with pytest.raises(ParserError):
        analyze_dataset(rows, columns, min_group_size=threshold)


@pytest.mark.parametrize("suffix, text", [
    ("csv", "age,age\n40,50\n"), ("csv", "age,town\n40\n"),
    ("json", '[{"age": 40, "age": 50}]'), ("json", '[1,2]'),
    ("json", '[{"age": NaN}]'), ("txt", "age\n40\n"),
])
def test_schema_ambiguity_does_not_silently_change_measurements(tmp_path, suffix, text):
    path = tmp_path / ("source." + suffix)
    path.write_text(text)
    with pytest.raises(ParserError):
        read_dataset_file(path)


def test_one_batch_reuses_tokens_and_retains_normal_verification():
    first = Payload(kind="json", content={"name": "张三", "mrn": "SYNTH-MRN-001"})
    second = Payload(kind="csv", content="name,mrn\n李四,SYNTH-MRN-002\n张三,SYNTH-MRN-001\n")
    result = sanitize_dataset([first, second], "external_approved", "RESEARCH")
    assert all(item.verification and item.verification.passed for item in result.results)
    one = json.loads(result.results[0].sanitized_payload.content)
    two = result.results[1].sanitized_payload.content
    assert one["name"] in two and one["mrn"] in two
    for raw in ["张三", "李四", "SYNTH-MRN-001", "SYNTH-MRN-002"]:
        assert raw not in json.dumps(result.summary(), ensure_ascii=False)
        assert raw not in result.results[0].sanitized_payload.content + two
    # This profile tokenizes names and removes MRNs; only the two names enter the map.
    assert result.token_count == 2


def test_independent_payloads_retain_the_default_new_map_and_explicit_batches_can_exceed_999():
    tokens = TokenRegistry()
    for index in range(1000):
        tokens.token_for("PERSON_NAME", f"SYNTH-PRELOAD-{index}")
    guard = Guard(token_registry=tokens)
    result = guard.sanitize(Payload(kind="json", content={"name": "张三"}),
                            "external_approved", "RESEARCH")
    assert result.verification.passed
    assert "[PERSON_NAME_1001]" in result.sanitized_payload.content
    independent = Guard().sanitize(Payload(kind="json", content={"name": "李四"}),
                                   "external_approved", "RESEARCH")
    assert "[PERSON_NAME_001]" in independent.sanitized_payload.content


def test_batch_withheld_files_never_fall_back_to_their_input():
    source = Payload(kind="json", content={"phone": 13800000000})
    result = sanitize_dataset([source], "external_approved", "RESEARCH")
    assert result.results[0].sanitized_payload is None
    assert result.summary()["files"][0]["released"] is False
    assert "13800000000" not in json.dumps(result.summary())


def test_cli_combines_csv_and_json_but_does_not_report_values_or_source_names(tmp_path, capsys):
    first = tmp_path / "SYNTH-SOURCE-A.csv"
    first.write_text("age,town\n40,SYNTH-TOWN\n40,SYNTH-TOWN\n")
    second = tmp_path / "SYNTH-SOURCE-B.json"
    second.write_text(json.dumps([{"age": 40, "town": "SYNTH-TOWN"},
                                  {"age": 50, "town": "SYNTH-RARE-TOWN"}]))
    assert main(["dataset-risk", str(first), str(second), "--quasi-identifier", "age",
                 "--quasi-identifier", "town", "--min-group-size", "3"]) == EXIT_OK
    visible = capsys.readouterr().out
    report = json.loads(visible)
    assert report["row_count"] == 4 and report["size_histogram"] == [
        {"rows_per_group": 1, "groups": 1}, {"rows_per_group": 3, "groups": 1},
    ]
    for raw in ["SYNTH-TOWN", "SYNTH-RARE-TOWN", first.name, second.name]:
        assert raw not in visible


def test_cli_writes_only_private_verified_outputs_and_refuses_existing_directories(tmp_path, capsys):
    first, second = tmp_path / "first.json", tmp_path / "second.csv"
    first.write_text(json.dumps({"name": "张三"}))
    second.write_text("name\n张三\n李四\n")
    directory = tmp_path / "minimized"
    arguments = ["dataset-sanitize", str(first), str(second), "--recipient", "external_approved",
                 "--purpose", "research", "--output-dir", str(directory)]
    assert main(arguments) == EXIT_OK
    summary = json.loads(capsys.readouterr().out)
    assert len(summary["files"]) == 2
    assert directory.stat().st_mode & 0o777 == 0o700
    for name in ["001.json", "002.csv", "manifest.json"]:
        assert (directory / name).stat().st_mode & 0o777 == 0o600
        assert "张三" not in (directory / name).read_text()
    original = (directory / "manifest.json").read_bytes()
    assert main(arguments) == EXIT_ERROR
    assert (directory / "manifest.json").read_bytes() == original


def test_cli_reports_ask_without_copying_the_withheld_source(tmp_path, capsys):
    source = tmp_path / "source.json"
    source.write_text('{"phone": 13800000000}')
    directory = tmp_path / "out"
    assert main(["dataset-sanitize", str(source), "--recipient", "external_approved",
                 "--output-dir", str(directory)]) == EXIT_ASK
    assert not (directory / "001.json").exists()
    assert "13800000000" not in (directory / "manifest.json").read_text()
    assert not json.loads(capsys.readouterr().out)["files"][0]["released"]


@pytest.mark.parametrize("alias", ["hardlink", "symlink"])
def test_dataset_audit_alias_is_rejected_before_any_input_or_output_changes(tmp_path, alias, capsys):
    source = tmp_path / "source.json"
    source.write_text('{"name":"SYNTH-NAME"}\n')
    audit = tmp_path / "audit"
    audit.mkdir()
    if alias == "hardlink":
        os.link(source, audit / "events.jsonl")
    else:
        (audit / "events.jsonl").symlink_to(source)
    original, mode = source.read_bytes(), source.stat().st_mode
    output = tmp_path / "output"
    assert main(["dataset-sanitize", str(source), "--recipient", "external_approved",
                 "--output-dir", str(output), "--audit-dir", str(audit)]) == EXIT_ERROR
    assert source.read_bytes() == original and source.stat().st_mode == mode
    assert not output.exists() and not capsys.readouterr().out


@pytest.mark.parametrize("nested", [False, True])
def test_audit_directory_cannot_create_the_dataset_output_before_publication(tmp_path, nested, capsys):
    source = tmp_path / "source.csv"
    source.write_text("age\n40\n")
    output = tmp_path / "output"
    audit = output / "audit" if nested else output
    assert main(["dataset-sanitize", str(source), "--recipient", "external_approved",
                 "--output-dir", str(output), "--audit-dir", str(audit)]) == EXIT_ERROR
    assert not output.exists() and not capsys.readouterr().out


@pytest.mark.parametrize("literal", ["1e999", "-1e999"])
def test_nonfinite_json_numbers_are_rejected_even_outside_selected_columns(tmp_path, literal, capsys):
    source = tmp_path / "source.json"
    source.write_text('[{"age":40,"extra":{"value":' + literal + '}}]')
    with pytest.raises(ParserError):
        read_dataset_file(source)
    assert main(["dataset-risk", str(source), "--quasi-identifier", "age"]) == EXIT_ERROR
    assert not capsys.readouterr().out


def test_dataset_write_failure_retains_only_private_verified_partial_evidence(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source.json"
    source.write_text('{"name":"张三"}')
    original = source.read_bytes()
    output = tmp_path / "output"

    def fail_sync(descriptor):
        raise OSError("synthetic output synchronization failure")

    monkeypatch.setattr(os, "fsync", fail_sync)
    assert main(["dataset-sanitize", str(source), "--recipient", "external_approved",
                 "--output-dir", str(output)]) == EXIT_ERROR
    assert not capsys.readouterr().out and not (output / "manifest.json").exists()
    partial = output / "001.json"
    assert partial.is_file() and partial.stat().st_mode & 0o777 == 0o600
    assert "张三" not in partial.read_text() and source.read_bytes() == original
