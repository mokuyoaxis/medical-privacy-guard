"""The Anthropic wrapper: same verdict semantics, different request shape.

The stub records the kwargs that would have gone over the wire, so every
assertion is about the released request body.
"""

from __future__ import annotations

import pytest

from adapters.anthropic_compat import AnthropicGuard
from core.errors import DisclosureBlocked, HumanApprovalRequired
from medical_privacy_guard import Guard


class StubTransport:
    def __init__(self) -> None:
        self.requests: list[dict] = []

    def messages_create(self, **kwargs):
        self.requests.append(kwargs)
        return {"id": "msg_1", "role": "assistant", "content": [{"type": "text", "text": "ok"}]}


class StubClient:
    def __init__(self, transport: StubTransport) -> None:
        class _Messages:
            @staticmethod
            def create(**kwargs):
                return transport.messages_create(**kwargs)

        self.messages = _Messages()


@pytest.fixture(scope="module")
def guard() -> Guard:
    return Guard(profile="external-ai-strict")


@pytest.fixture()
def transport() -> StubTransport:
    return StubTransport()


@pytest.fixture()
def client(guard, transport) -> AnthropicGuard:
    return AnthropicGuard(StubClient(transport), guard, recipient="external_unknown")


class TestSystemField:
    def test_a_system_prompt_is_sanitized(self, client, transport):
        client.messages.create(
            model="claude", max_tokens=10,
            system="你是协和医院心内科的随访助手",  # 合成机构名示例
            messages=[{"role": "user", "content": "你好"}],
        )
        sent = transport.requests[0]["system"]
        assert "协和医院" not in sent or "[INSTITUTION" in sent

    def test_a_system_block_list_is_handled_per_block(self, client, transport):
        client.messages.create(
            model="claude", max_tokens=10,
            system=[
                {"type": "text", "text": "患者姓名：张三"},
                {"type": "text", "text": "随访助手"},
            ],
            messages=[{"role": "user", "content": "你好"}],
        )
        blocks = transport.requests[0]["system"]
        assert "张三" not in blocks[0]["text"]
        assert blocks[1]["text"] == "随访助手"


class TestContentBlocks:
    def test_text_blocks_are_sanitized(self, client, transport):
        client.messages.create(
            model="claude", max_tokens=10,
            messages=[{"role": "user", "content": [
                {"type": "text", "text": "患者姓名：张三"},
                {"type": "text", "text": "今日随访无异常"},
            ]}],
        )
        blocks = transport.requests[0]["messages"][0]["content"]
        assert "张三" not in blocks[0]["text"]
        assert blocks[1]["text"] == "今日随访无异常"

    def test_a_string_content_is_sanitized(self, client, transport):
        client.messages.create(
            model="claude", max_tokens=10,
            messages=[{"role": "user", "content": "患者张三的电话13800000000"}],
        )
        sent = transport.requests[0]["messages"][0]["content"]
        assert "13800000000" not in sent

    def test_tool_use_input_is_sanitized_as_json(self, client, transport):
        client.messages.create(
            model="claude", max_tokens=10,
            messages=[{"role": "assistant", "content": [
                {"type": "tool_use", "id": "t1", "name": "lookup", "input": {"name": "John Smith"}},
            ]}],
        )
        sent = transport.requests[0]["messages"][0]["content"][0]["input"]
        assert sent["name"] == "[PERSON_NAME_001]"

    def test_tool_result_text_is_sanitized(self, client, transport):
        client.messages.create(
            model="claude", max_tokens=10,
            messages=[{"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": "病历号 ZY2026001"},
            ]}],
        )
        sent = transport.requests[0]["messages"][0]["content"][0]["content"]
        assert "ZY2026001" not in sent

    def test_an_image_block_fails_closed(self, client, transport):
        from core.errors import VerificationFailed

        with pytest.raises((VerificationFailed, DisclosureBlocked)):
            client.messages.create(
                model="claude", max_tokens=10,
                messages=[{"role": "user", "content": [
                    {"type": "image", "source": {"type": "base64", "data": "x"}},
                ]}],
            )
        assert transport.requests == []


class TestVerdicts:
    def test_block_raises_and_nothing_is_sent(self, client, transport):
        with pytest.raises(DisclosureBlocked):
            client.messages.create(
                model="claude", max_tokens=10,
                system="身份证号 110101199003078888",
                messages=[{"role": "user", "content": "你好"}],
            )
        assert transport.requests == []

    def test_ask_raises(self, guard, transport):
        wrapped = AnthropicGuard(StubClient(transport), guard, recipient="external_unknown")
        with pytest.raises(HumanApprovalRequired):
            wrapped.messages.create(
                model="claude", max_tokens=10,
                messages=[{"role": "user", "content": "本县唯一一名103岁患者"}],
            )
        assert transport.requests == []


class TestSideFields:
    def test_tool_description_block_refuses_the_call(self, client, transport):
        with pytest.raises(DisclosureBlocked):
            client.messages.create(
                model="claude", max_tokens=10,
                messages=[{"role": "user", "content": "你好"}],
                tools=[{"name": "t", "description": "身份证号 110101199003078888",
                        "input_schema": {"type": "object", "properties": {}}}],
            )
        assert transport.requests == []

    def test_metadata_user_id_is_evaluated_and_never_rewritten(self, client, transport):
        with pytest.raises(DisclosureBlocked):
            client.messages.create(
                model="claude", max_tokens=10,
                messages=[{"role": "user", "content": "你好"}],
                metadata={"user_id": "身份证号 110101199003078888"},
            )
        assert transport.requests == []

    def test_model_and_sampling_fields_pass_through(self, client, transport):
        client.messages.create(
            model="claude", max_tokens=10, temperature=0.2, top_p=0.9,
            messages=[{"role": "user", "content": "你好"}],
        )
        sent = transport.requests[0]
        assert sent["temperature"] == 0.2 and sent["top_p"] == 0.9
