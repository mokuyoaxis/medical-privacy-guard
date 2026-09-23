"""CSV payload support.

Column detection is two-sided on purpose. **Column names** supply the field
label, which is what makes a value detectable at all; **cell scanning** is the
source of truth for facts, because a header can be wrong, missing or
duplicated. A table with unconventional headers simply gets no labels and still
has its cells scanned.

Token consistency is a file-level property: the same patient name appearing in
several rows must map to the same token, or the released table leaks which rows
belong together beyond what the values already said.
"""

from __future__ import annotations

import csv
import io
import json

import pytest

from core.model import Payload, Purpose, Recipient, TrustLevel
from formats import dumps_csv, parse_csv_payload, rebuild_csv
from medical_privacy_guard import Guard

TABLE = "姓名,电话,年龄,备注\n张三,13800000000,67,因脑梗死入院\n李四,13900000000,45,普通随访\n"


@pytest.fixture(scope="module")
def guard() -> Guard:
    return Guard(profile="external-ai-strict")


@pytest.fixture(scope="module")
def approved() -> Recipient:
    return Recipient(kind="test", trust_level=TrustLevel("EXTERNAL_APPROVED"))


def sanitize_csv(guard, recipient, text):
    return guard.sanitize(
        Payload(kind="csv", content=text), recipient, Purpose.EXTERNAL_AI_ASSISTANCE
    )


def rows_of(text: str) -> list[list[str]]:
    return [row for row in csv.reader(io.StringIO(text))]


# -- parsing -----------------------------------------------------------------


class TestCsvParsing:
    def test_header_is_detected_from_field_names(self):
        parsed = parse_csv_payload(TABLE)
        assert parsed.document.header == ("姓名", "电话", "年龄", "备注")
        assert len(parsed.document.rows) == 2

    def test_headerless_table_is_all_data(self):
        parsed = parse_csv_payload("张三,13800000000\n李四,13900000000\n")
        assert parsed.document.header is None
        assert len(parsed.document.rows) == 2

    def test_cells_carry_the_column_label(self):
        parsed = parse_csv_payload(TABLE)
        labels = {(leaf.path, leaf.label) for leaf in parsed.leaves}
        assert ("row[0].col[0]", "姓名") in labels
        assert ("row[0].col[3]", None) in labels  # 备注 is not a recognised label

    def test_english_headers_resolve(self):
        parsed = parse_csv_payload("patient_name,phone\n张三,13800000000\n")
        assert [leaf.label for leaf in parsed.leaves] == ["患者姓名", "电话"]

    def test_quoted_fields_with_delimiters(self):
        parsed = parse_csv_payload('姓名,备注\n张三,"因脑梗死入院, 伴高血压"\n')
        values = [leaf.text for leaf in parsed.leaves]
        assert "因脑梗死入院, 伴高血压" in values

    def test_ragged_rows_are_preserved(self):
        parsed = parse_csv_payload("姓名,电话,年龄\n张三,13800000000\n")
        assert parsed.document.rows == (("张三", "13800000000"),)

    @pytest.mark.parametrize("text", ["", "\n"])
    def test_empty_payload_is_rejected(self, text):
        from core.errors import ParserError

        with pytest.raises(ParserError):
            parse_csv_payload(text)

    def test_oversized_field_is_rejected(self):
        from core.errors import ParserError

        original = csv.field_size_limit()
        csv.field_size_limit(64)
        try:
            with pytest.raises(ParserError):
                parse_csv_payload("姓名\n" + "x" * 500 + "\n")
        finally:
            csv.field_size_limit(original)


# -- rebuilding --------------------------------------------------------------


class TestCsvRebuild:
    def test_structure_is_preserved(self):
        parsed = parse_csv_payload(TABLE)
        rebuilt = rebuild_csv(parsed.document, {"row[0].col[0]": "[PERSON_NAME_001]"})
        assert rebuilt.header == parsed.document.header
        assert len(rebuilt.rows) == len(parsed.document.rows)
        assert rebuilt.rows[0][0] == "[PERSON_NAME_001]"
        assert rebuilt.rows[0][1] == "13800000000"
        assert rebuilt.rows[1][0] == "李四"

    def test_the_original_is_not_mutated(self):
        parsed = parse_csv_payload(TABLE)
        rebuild_csv(parsed.document, {"row[0].col[0]": "x"})
        assert parsed.document.rows[0][0] == "张三"

    def test_a_path_outside_the_table_is_an_error(self):
        from core.errors import ParserError

        parsed = parse_csv_payload(TABLE)
        with pytest.raises(ParserError):
            rebuild_csv(parsed.document, {"row[99].col[0]": "x"})

    def test_round_trip_is_stable(self):
        parsed = parse_csv_payload(TABLE)
        assert dumps_csv(parsed.document) == TABLE


# -- end to end --------------------------------------------------------------


class TestCsvPipeline:
    def test_cells_are_sanitized_and_the_table_survives(self, guard, approved):
        result = sanitize_csv(guard, approved, TABLE)
        assert result.decision_before.verdict.value == "SANITIZE"
        assert result.verification is not None and result.verification.passed
        out = rows_of(result.sanitized_payload.content)
        assert out[0] == ["姓名", "电话", "年龄", "备注"]
        assert out[1][0] == "[PERSON_NAME_001]"
        assert out[1][1] == "[REDACTED]"
        assert out[1][2] == "67"
        assert out[1][3] == "因脑梗死入院"
        assert out[2][0] == "[PERSON_NAME_002]"

    def test_the_same_name_maps_to_the_same_token(self, guard, approved):
        """A file-level property: row identity must not leak through tokens."""
        table = "姓名,备注\n张三,首次就诊\n张三,复诊\n"
        result = sanitize_csv(guard, approved, table)
        out = rows_of(result.sanitized_payload.content)
        assert out[1][0] == out[2][0]

    def test_different_names_get_different_tokens(self, guard, approved):
        result = sanitize_csv(guard, approved, TABLE)
        out = rows_of(result.sanitized_payload.content)
        assert out[1][0] != out[2][0]

    def test_adjacent_cells_do_not_form_a_false_match(self, guard, approved):
        """Cells are joined with NUL when flattened, so columns cannot merge."""
        table = "a,b\n患者张,三入院\n"
        result = sanitize_csv(guard, approved, table)
        assert result.decision_before.verdict.value == "ALLOW"

    def test_headerless_table_still_scans_cells(self, guard, approved):
        table = "张三,13800000000\n"
        result = sanitize_csv(guard, approved, table)
        out = rows_of(result.sanitized_payload.content)
        assert out[0][1] == "[REDACTED]"

    def test_audit_counts_cover_every_cell(self, tmp_path):
        audit_dir = tmp_path / "audit"
        guarded = Guard(profile="external-ai-strict", audit_dir=str(audit_dir))
        sanitize_csv(guarded, Recipient(kind="t", trust_level=TrustLevel("EXTERNAL_APPROVED")), TABLE)
        event = json.loads((audit_dir / "events.jsonl").read_text(encoding="utf-8").strip())
        # Every cell is counted, not just the first: 备注 contributes a
        # medical-content signal on top of the identifiers.
        assert event["entity_counts"]["PERSON_NAME"] == 2
        assert event["entity_counts"]["PHONE"] == 2
        assert event["entity_counts"]["MEDICAL_CONTENT"] == 1  # 入院 in the first row only
        stream = (audit_dir / "events.jsonl").read_text(encoding="utf-8")
        assert "张三" not in stream and "13800000000" not in stream
