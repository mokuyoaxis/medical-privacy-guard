"""The OpenAI-compatible wrapper: same verdict semantics as every adapter.

The stub transport records what would have gone over the wire, so these tests
assert on the request body the guard released -- the same assertion an operator
would make with a wire tap, without one.
"""

from __future__ import annotations

import json

import pytest

from adapters.openai_compat import OpenAIGuard
from core.errors import DisclosureBlocked, HumanApprovalRequired
from medical_privacy_guard import Guard


class StubTransport:
    """Records kwargs and returns a fixed completion."""

    def __init__(self) -> None:
        self.requests: list[dict] = []

    def chat_completions_create(self, **kwargs):
        self.requests.append(kwargs)
        return {"id": "resp_1", "choices": [{"message": {"role": "assistant", "content": "ok"}}]}


@pytest.fixture(scope="module")
def guard() -> Guard:
    return Guard(profile="external-ai-strict")


@pytest.fixture()
def transport() -> StubTransport:
    return StubTransport()


class StubClient:
    """Duck-typed ``client`` shell: ``client.chat.completions.create``."""

    def __init__(self, transport: StubTransport) -> None:
        class _Completions:
            @staticmethod
            def create(**kwargs):
                return transport.chat_completions_create(**kwargs)

        class _Chat:
            completions = _Completions()

        self.chat = _Chat()


@pytest.fixture()
def client(guard, transport) -> OpenAIGuard:
    return OpenAIGuard(StubClient(transport), guard, recipient="external_unknown")


class TestMessageContent:
    def test_a_plain_message_with_phi_is_sanitized(self, client, transport):
        client.chat.completions.create(
            model="x", messages=[{"role": "user", "content": "患者姓名：张三，电话13800000000"}]
        )
        sent = transport.requests[0]["messages"][0]["content"]
        assert "张三" not in sent and "13800000000" not in sent
        assert "PERSON_NAME_001" in sent

    def test_an_english_keyed_tool_argument_is_sanitized(self, client, transport):
        client.chat.completions.create(
            model="x",
            messages=[
                {
                    "role": "assistant",
                    "tool_calls": [
                        {"function": {"name": "lookup", "arguments": json.dumps({"name": "John Smith"})}}
                    ],
                }
            ],
        )
        sent = json.loads(
            transport.requests[0]["messages"][0]["tool_calls"][0]["function"]["arguments"]
        )
        assert sent["name"] == "[PERSON_NAME_001]"

    def test_content_parts_are_sanitized_in_place(self, client, transport):
        client.chat.completions.create(
            model="x",
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "患者：张三"},
                        {"type": "text", "text": "随访无异常"},
                    ],
                }
            ],
        )
        parts = transport.requests[0]["messages"][0]["content"]
        assert "张三" not in parts[0]["text"]
        assert parts[1]["text"] == "随访无异常"

    def test_an_image_part_fails_closed(self, client, transport):
        from core.errors import VerificationFailed

        with pytest.raises((VerificationFailed, DisclosureBlocked)):
            client.chat.completions.create(
                model="x",
                messages=[
                    {"role": "user", "content": [{"type": "image_url", "image_url": {"url": "x"}}]}
                ],
            )
        assert transport.requests == []


class TestVerdicts:
    def test_block_raises_and_nothing_is_sent(self, client, transport):
        with pytest.raises(DisclosureBlocked):
            client.chat.completions.create(
                model="x",
                messages=[{"role": "user", "content": "身份证号 110101199003078888"}],
            )
        assert transport.requests == []

    def test_ask_raises(self, guard, transport):
        wrapped = OpenAIGuard(StubClient(transport), guard, recipient="external_unknown")
        with pytest.raises(HumanApprovalRequired):
            wrapped.chat.completions.create(
                model="x",
                messages=[{"role": "user", "content": "本县唯一一名103岁患者"}],
            )
        assert transport.requests == []


class TestSideFields:
    def test_metadata_is_evaluated_and_rewritten(self, client, transport):
        client.chat.completions.create(
            model="x",
            messages=[{"role": "user", "content": "你好"}],
            metadata={"note": "姓名：张三"},
        )
        sent = transport.requests[0]["metadata"]
        assert sent["note"] == "姓名：[PERSON_NAME_001]"

    def test_a_blocked_user_identifier_refuses_the_call(self, client, transport):
        with pytest.raises(DisclosureBlocked):
            client.chat.completions.create(
                model="x",
                messages=[{"role": "user", "content": "你好"}],
                user="身份证号 110101199003078888",
            )
        assert transport.requests == []

    def test_tool_description_block_refuses_the_call(self, client, transport):
        with pytest.raises(DisclosureBlocked):
            client.chat.completions.create(
                model="x",
                messages=[{"role": "user", "content": "你好"}],
                tools=[
                    {
                        "type": "function",
                        "function": {
                            "name": "t",
                            "description": "身份证号 110101199003078888",
                            "parameters": {"type": "object", "properties": {}},
                        },
                    }
                ],
            )
        assert transport.requests == []
