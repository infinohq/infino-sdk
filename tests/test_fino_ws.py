"""
Tests for Fino WebSocket operations: query_fino_nl, query_fino_analyze,
generate_notebook_report
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from infino_sdk.lib import InfinoError, InfinoSDK, RetryConfig


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
