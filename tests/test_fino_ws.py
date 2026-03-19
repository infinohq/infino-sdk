"""
Tests for Fino WebSocket operations: query_fino_nl, query_fino_analyze,
generate_notebook_report, FinoWebSocketClient
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from infino_sdk.lib import FinoWebSocketClient, InfinoError, InfinoSDK, RetryConfig


def _make_sdk():
    """Create SDK with mocked HTTP session for thread creation."""
    retry_config = RetryConfig()
    retry_config.max_retries = 1
    retry_config.initial_interval = 10
    retry_config.max_interval = 10

    sdk = InfinoSDK(
        "test_access", "test_secret", "https://test.infino.ws", retry_config
    )

    mock_session = MagicMock()
    thread_response = Mock()
    thread_response.status_code = 200
    thread_response.text = json.dumps({"id": "thread-001", "name": "sdk-query"})
    mock_session.request.return_value = thread_response

    sdk.session = mock_session
    return sdk


class FakeWebSocket:
    """Fake async WebSocket that yields pre-configured messages."""

    def __init__(self, messages):
        self._messages = messages
        self._sent = []
        self._closed = False

    async def send(self, data):
        self._sent.append(data)

    async def close(self):
        self._closed = True

    def __aiter__(self):
        return self._aiter()

    async def _aiter(self):
        for msg in self._messages:
            yield msg


class TestQueryFinoNl:
    """Test query_fino_nl WebSocket method"""

    @pytest.mark.asyncio
    async def test_nl_query_returns_result(self):
        """Test NL query receiving a search-style result message"""
        sdk = _make_sdk()

        result_msg = json.dumps(
            {
                "role": "assistant",
                "content": {
                    "type": "result",
                    "summary": "There were 42 errors in the last hour.",
                    "data": {"count": 42},
                    "querydsl": {"query": {"match_all": {}}},
                    "sql": None,
                },
            }
        )

        fake_ws = FakeWebSocket([result_msg])

        with patch.object(
            sdk, "websocket_connect", new_callable=AsyncMock, return_value=fake_ws
        ):
            result = await sdk.query_fino_nl("How many errors in the last hour?")

        assert result["answer"] == "There were 42 errors in the last hour."
        assert result["data"]["count"] == 42
        assert result["querydsl"] is not None
        assert fake_ws._closed

    @pytest.mark.asyncio
    async def test_nl_query_handles_error(self):
        """Test NL query receiving an error response"""
        sdk = _make_sdk()

        error_msg = json.dumps(
            {
                "role": "assistant",
                "content": {
                    "type": "error",
                    "error_message": "No dataset found",
                },
            }
        )

        fake_ws = FakeWebSocket([error_msg])

        with patch.object(
            sdk, "websocket_connect", new_callable=AsyncMock, return_value=fake_ws
        ):
            with pytest.raises(InfinoError) as exc_info:
                await sdk.query_fino_nl("query something")

        assert "No dataset found" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_nl_query_sends_correct_message_format(self):
        """Test that NL query sends the correct search-handler format"""
        sdk = _make_sdk()

        result_msg = json.dumps(
            {
                "role": "assistant",
                "content": {"type": "message", "summary": "ok", "data": {}},
            }
        )

        fake_ws = FakeWebSocket([result_msg])

        with patch.object(
            sdk, "websocket_connect", new_callable=AsyncMock, return_value=fake_ws
        ):
            await sdk.query_fino_nl("test query")

        assert len(fake_ws._sent) == 1
        sent = json.loads(fake_ws._sent[0])
        assert sent["role"] == "user"
        assert sent["content"]["user_query"] == "test query"
        assert sent["content"]["type"] == "user"
        assert sent["content"]["sender_agent"] == "user"
        assert "id" in sent
        assert "created_at" in sent


    @pytest.mark.asyncio
    async def test_nl_query_includes_streaming_response_with_progress_frames(self):
        """Test that NL query result includes all websocket frames in streaming_response"""
        sdk = _make_sdk()

        update_msg = json.dumps(
            {
                "role": "assistant",
                "content": {
                    "type": "update",
                    "sender": "router",
                    "message": "Routing message to SQL generation",
                },
            }
        )
        partial_msg = json.dumps(
            {
                "role": "assistant",
                "content": {
                    "type": "partial",
                    "key": "sql",
                    "sender": "sql_gen",
                },
            }
        )
        result_msg = json.dumps(
            {
                "role": "assistant",
                "content": {
                    "type": "result",
                    "summary": "Found 10 errors.",
                    "data": {"count": 10},
                },
            }
        )

        fake_ws = FakeWebSocket([update_msg, partial_msg, result_msg])

        with patch.object(
            sdk, "websocket_connect", new_callable=AsyncMock, return_value=fake_ws
        ):
            result = await sdk.query_fino_nl("How many errors?")

        assert result["answer"] == "Found 10 errors."
        assert "streaming_response" in result
        assert len(result["streaming_response"]) == 3
        assert result["streaming_response"][0]["content"]["type"] == "update"
        assert (
            result["streaming_response"][0]["content"]["message"]
            == "Routing message to SQL generation"
        )
        assert result["streaming_response"][1]["content"]["type"] == "partial"
        assert result["streaming_response"][2]["content"]["type"] == "result"


    @pytest.mark.asyncio
    async def test_nl_query_calls_on_message_for_each_frame(self):
        """Test that on_message is called for every incoming frame, including intermediates"""
        sdk = _make_sdk()

        update_msg = json.dumps({"role": "assistant", "content": {"type": "update", "message": "Routing query"}})
        result_msg = json.dumps({"role": "assistant", "content": {"type": "result", "summary": "Done.", "data": {}}})
        fake_ws = FakeWebSocket([update_msg, result_msg])

        received: list = []
        with patch.object(sdk, "websocket_connect", new_callable=AsyncMock, return_value=fake_ws):
            result = await sdk.query_fino_nl("test", on_message=received.append)

        assert result["answer"] == "Done."
        assert len(received) == 2
        assert received[0]["content"]["type"] == "update"
        assert received[1]["content"]["type"] == "result"


class TestQueryFinoAnalyze:
    """Test query_fino_analyze WebSocket method"""

    @pytest.mark.asyncio
    async def test_analyze_query_returns_responses(self):
        """Test analyze query collecting responses until EOM"""
        sdk = _make_sdk()

        action_msg = json.dumps(
            {
                "type": "analyze_action",
                "action": "create_cell",
                "cell": {"code": "SELECT COUNT(*) FROM logs"},
            }
        )
        eom_msg = json.dumps({"type": "EOM"})

        fake_ws = FakeWebSocket([action_msg, eom_msg])

        with patch.object(
            sdk, "websocket_connect", new_callable=AsyncMock, return_value=fake_ws
        ):
            result = await sdk.query_fino_analyze("Analyze error trends")

        assert "responses" in result
        assert len(result["responses"]) == 2
        assert result["responses"][0]["type"] == "analyze_action"
        assert result["responses"][1]["type"] == "EOM"

    @pytest.mark.asyncio
    async def test_analyze_query_sends_correct_format(self):
        """Test that analyze query sends the correct analyze-handler format"""
        sdk = _make_sdk()

        eom_msg = json.dumps({"type": "EOM"})
        fake_ws = FakeWebSocket([eom_msg])

        with patch.object(
            sdk, "websocket_connect", new_callable=AsyncMock, return_value=fake_ws
        ):
            await sdk.query_fino_analyze("analyze this")

        assert len(fake_ws._sent) == 1
        sent = json.loads(fake_ws._sent[0])
        assert sent["type"] == "analyze"
        assert sent["request"] == "analyze this"
        assert "notebook" in sent
        assert sent["notebook"]["tables"] == []
        assert sent["notebook"]["cells"] == []

    @pytest.mark.asyncio
    async def test_analyze_query_handles_top_level_error(self):
        """Test analyze query receiving a top-level error message"""
        sdk = _make_sdk()

        error_msg = json.dumps(
            {
                "type": "error",
                "message": "Analysis failed: no data sources",
            }
        )

        fake_ws = FakeWebSocket([error_msg])

        with patch.object(
            sdk, "websocket_connect", new_callable=AsyncMock, return_value=fake_ws
        ):
            with pytest.raises(InfinoError) as exc_info:
                await sdk.query_fino_analyze("analyze something")

        assert "no data sources" in exc_info.value.message


    @pytest.mark.asyncio
    async def test_analyze_query_calls_on_message_for_each_frame(self):
        """Test that on_message is called for every incoming frame"""
        sdk = _make_sdk()

        action_msg = json.dumps({"type": "analyze_action", "action": "create_cell"})
        eom_msg = json.dumps({"type": "EOM"})
        fake_ws = FakeWebSocket([action_msg, eom_msg])

        received: list = []
        with patch.object(sdk, "websocket_connect", new_callable=AsyncMock, return_value=fake_ws):
            await sdk.query_fino_analyze("test", on_message=received.append)

        assert len(received) == 2
        assert received[0]["type"] == "analyze_action"
        assert received[1]["type"] == "EOM"


class TestGenerateNotebookReport:
    """Test generate_notebook_report WebSocket method"""

    @pytest.mark.asyncio
    async def test_report_returns_summary(self):
        """Test report generation returning a summary"""
        sdk = _make_sdk()

        partial_msg = json.dumps(
            {
                "type": "partial",
                "sub_type": "summary",
                "value": "## Executive Summary\n\nThe analysis shows...",
            }
        )

        fake_ws = FakeWebSocket([partial_msg])

        with patch.object(
            sdk, "websocket_connect", new_callable=AsyncMock, return_value=fake_ws
        ):
            report = await sdk.generate_notebook_report(
                "nb-001", report_type="executive"
            )

        assert "Executive Summary" in report
        assert fake_ws._closed

    @pytest.mark.asyncio
    async def test_report_handles_eom_without_summary(self):
        """Test report returning empty string when EOM arrives without summary"""
        sdk = _make_sdk()

        eom_msg = json.dumps({"type": "EOM"})
        fake_ws = FakeWebSocket([eom_msg])

        with patch.object(
            sdk, "websocket_connect", new_callable=AsyncMock, return_value=fake_ws
        ):
            report = await sdk.generate_notebook_report("nb-002")

        assert report == ""

    @pytest.mark.asyncio
    async def test_report_handles_error(self):
        """Test report generation error"""
        sdk = _make_sdk()

        error_msg = json.dumps(
            {
                "type": "error",
                "error_message": "Notebook not found",
            }
        )
        fake_ws = FakeWebSocket([error_msg])

        with patch.object(
            sdk, "websocket_connect", new_callable=AsyncMock, return_value=fake_ws
        ):
            with pytest.raises(InfinoError) as exc_info:
                await sdk.generate_notebook_report("nb-999")

        assert "Notebook not found" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_report_sends_correct_message(self):
        """Test that report sends the correct generate_report message"""
        sdk = _make_sdk()

        eom_msg = json.dumps({"type": "EOM"})
        fake_ws = FakeWebSocket([eom_msg])

        cache = {
            "execution_results": {"cell-1": {"output": "42"}},
            "user_requests": "Summarize error trends",
        }

        with patch.object(
            sdk, "websocket_connect", new_callable=AsyncMock, return_value=fake_ws
        ):
            await sdk.generate_notebook_report(
                "nb-003", report_type="short", analysis_cache=cache
            )

        assert len(fake_ws._sent) == 1
        sent = json.loads(fake_ws._sent[0])
        assert sent["type"] == "generate_report"
        assert sent["report_type"] == "short"
        assert "analysis_cache" in sent
        assert sent["analysis_cache"]["user_requests"] == "Summarize error trends"

    @pytest.mark.asyncio
    async def test_report_without_cache(self):
        """Test report generation without analysis cache"""
        sdk = _make_sdk()

        eom_msg = json.dumps({"type": "EOM"})
        fake_ws = FakeWebSocket([eom_msg])

        with patch.object(
            sdk, "websocket_connect", new_callable=AsyncMock, return_value=fake_ws
        ):
            await sdk.generate_notebook_report("nb-004")

        sent = json.loads(fake_ws._sent[0])
        assert "analysis_cache" not in sent


class TestFinoWebSocketClient:
    """Unit tests for FinoWebSocketClient"""

    def _make_client(self, ws_path: str = "/fino/nl") -> tuple:
        sdk = _make_sdk()
        client = FinoWebSocketClient(sdk, "thread-001", ws_path, "test-client")
        return client, sdk

    def test_full_path_encodes_thread_and_client_ids(self) -> None:
        client, _ = self._make_client()
        path = client._full_path()
        assert "threadId=thread-001" in path
        assert "clientId=test-client" in path

    def test_full_path_url_encodes_special_chars(self) -> None:
        sdk = _make_sdk()
        client = FinoWebSocketClient(sdk, "my thread", "/fino/nl", "my app")
        path = client._full_path()
        assert "threadId=my%20thread" in path
        assert "clientId=my%20app" in path

    @pytest.mark.asyncio
    async def test_send_returns_false_when_not_connected(self) -> None:
        client, _ = self._make_client()
        # send() returns False and queues the message when not connected.
        # Set intentionally_closed so the auto-reconnect task created internally
        # exits immediately without leaking into subsequent tests.
        client._intentionally_closed = True
        assert client.send({"hello": "world"}) is False

    def test_is_connected_false_before_connect(self) -> None:
        client, _ = self._make_client()
        assert client.is_connected() is False

    def test_on_frame_receives_dispatched_frames(self) -> None:
        """on_frame handlers are called when frames are dispatched."""
        client, _ = self._make_client()
        frames: list = []
        client.on_frame(frames.append)

        # Dispatch frames directly, bypassing the receive loop.
        for handler in list(client._frame_handlers):
            handler({"type": "update", "message": "routing"})
        for handler in list(client._frame_handlers):
            handler({"role": "assistant", "content": {"type": "result", "summary": "done"}})

        assert len(frames) == 2
        assert frames[0]["type"] == "update"
        assert frames[1]["content"]["type"] == "result"

    def test_on_frame_unsubscribe_stops_delivery(self) -> None:
        """Unsubscribing prevents further frame delivery."""
        client, _ = self._make_client()
        frames: list = []
        unsub = client.on_frame(frames.append)
        unsub()

        for handler in list(client._frame_handlers):
            handler({"type": "result"})

        assert len(frames) == 0

    @pytest.mark.asyncio
    async def test_send_returns_true_when_connected(self) -> None:
        client, _ = self._make_client()
        fake_ws = FakeWebSocket([])
        # Bypass connect() entirely — inject _ws directly to test the send logic.
        client._ws = fake_ws
        client._intentionally_closed = True  # prevent any reconnect scheduling
        assert client.send({"type": "ping"}) is True
        await asyncio.sleep(0)
        client._ws = None

    @pytest.mark.asyncio
    async def test_nl_send_uses_correct_message_shape(self) -> None:
        client, _ = self._make_client("/fino/nl")
        fake_ws = FakeWebSocket([])
        client._ws = fake_ws
        client._intentionally_closed = True
        client.send({
            "id": "msg-1",
            "role": "user",
            "created_at": "2026-01-01T00:00:00Z",
            "content": {
                "user_query": "hello",
                "type": "user",
                "summary": "",
                "data": {},
                "vegaspec": {},
                "querydsl": {},
                "followup_queries": [],
                "sender_agent": "user",
                "user_context": {},
            },
        })
        await asyncio.sleep(0)  # let create_task execute _send_raw
        client._ws = None

        assert len(fake_ws._sent) == 1
        sent = json.loads(fake_ws._sent[0])
        assert sent["content"]["user_query"] == "hello"
        assert sent["content"]["type"] == "user"
        assert sent["role"] == "user"
        assert sent["content"]["sender_agent"] == "user"

    @pytest.mark.asyncio
    async def test_analyze_send_uses_correct_message_shape(self) -> None:
        client, _ = self._make_client("/fino/analyze")
        fake_ws = FakeWebSocket([])
        client._ws = fake_ws
        client._intentionally_closed = True
        client.send({
            "type": "analyze",
            "request": "Why did errors spike?",
            "notebook": {"tables": [], "cells": [], "variables": [], "dataframes": {}, "attachments": []},
        })
        await asyncio.sleep(0)  # let create_task execute _send_raw
        client._ws = None

        assert len(fake_ws._sent) == 1
        sent = json.loads(fake_ws._sent[0])
        assert sent["type"] == "analyze"
        assert sent["request"] == "Why did errors spike?"
        assert sent["notebook"]["tables"] == []
        assert "role" not in sent

    @pytest.mark.asyncio
    async def test_close_sets_intentionally_closed(self) -> None:
        client, sdk = self._make_client()
        fake_ws = FakeWebSocket([])
        with patch.object(sdk, "websocket_connect", new_callable=AsyncMock, return_value=fake_ws):
            await client.connect()
            await client.close()
            # Allow the receive task to finish cancellation before the event loop moves on.
            await asyncio.sleep(0.05)
        assert client._intentionally_closed is True
        assert client._ws is None
