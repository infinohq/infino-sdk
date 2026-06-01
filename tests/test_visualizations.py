"""
Tests for visualization operations.

These exercise the v1 visualization API:
    POST   /visualizations          — lenient create (server fills defaults)
    GET    /visualizations          — list
    GET    /visualizations/:id      — fetch one
    DELETE /visualizations/:id      — delete
    POST   /visualizations/:id/data — execute and return {columns, rows, metadata}
"""

import json

import pytest

from infino_sdk.lib import InfinoError


@pytest.mark.unit
def test_create_visualization(sdk_with_mock_session, mock_response):
    """Caller sends a minimum body; server returns the full envelope."""
    sdk = sdk_with_mock_session

    server_envelope = {
        "id": "abc123",
        "kind": "visualization",
        "created_at": "2026-05-14T09:53:23Z",
        "updated_at": "2026-05-14T09:53:23Z",
        "attributes": {
            "schema_version": 1,
            "id": "abc123",
            "title": "Orders by currency",
            "source": {
                "kind": "sql",
                "index": "orders.rel",
                "sql": {
                    "raw_query": "SELECT currency, COUNT(*) AS count FROM orders.rel GROUP BY currency",
                    "dimensions": [],
                    "metrics": [],
                    "order_by": [],
                    "limit": 50,
                    "offset": 0,
                },
                "connection_id": None,
                "connector_id": None,
                "dsl": None,
                "promql": None,
            },
            "chart": {"type": "bar"},
            "mapping": {"x": None, "y": [], "series": None},
        },
    }
    sdk.session.request.return_value = mock_response(201, server_envelope)

    result = sdk.create_visualization(
        {
            "title": "Orders by currency",
            "source": {
                "kind": "sql",
                "index": "orders.rel",
                "sql": {
                    "raw_query": "SELECT currency, COUNT(*) AS count FROM orders.rel GROUP BY currency"
                },
            },
            "chart": {"type": "bar"},
        }
    )

    assert result["id"] == "abc123"
    assert result["attributes"]["title"] == "Orders by currency"
    assert result["attributes"]["source"]["sql"]["limit"] == 50  # server-filled default


@pytest.mark.unit
def test_create_visualization_missing_title_returns_400(
    sdk_with_mock_session, mock_response
):
    """Server rejects bodies missing required fields with 400."""
    sdk = sdk_with_mock_session

    sdk.session.request.return_value = mock_response(
        400,
        {
            "error": {"type": "ValidationError", "reason": "`title` is required"},
            "status": 400,
        },
    )

    with pytest.raises(InfinoError) as exc:
        sdk.create_visualization(
            {"source": {"kind": "sql", "index": "x"}, "chart": {"type": "bar"}}
        )
    assert exc.value.status_code() == 400


@pytest.mark.unit
def test_get_visualization(sdk_with_mock_session, mock_response):
    """Fetch a visualization by id."""
    sdk = sdk_with_mock_session

    envelope = {
        "id": "abc123",
        "kind": "visualization",
        "created_at": "2026-05-14T09:53:23Z",
        "updated_at": "2026-05-14T09:53:23Z",
        "attributes": {"title": "Orders by currency"},
    }
    sdk.session.request.return_value = mock_response(200, envelope)

    result = sdk.get_visualization("abc123")

    assert result["id"] == "abc123"
    assert result["attributes"]["title"] == "Orders by currency"


@pytest.mark.unit
def test_get_visualization_not_found(sdk_with_mock_session, mock_response):
    """Unknown ids return 404."""
    sdk = sdk_with_mock_session

    sdk.session.request.return_value = mock_response(
        404,
        {
            "error": {"type": "NotFound", "reason": "visualization 'nope' not found"},
            "status": 404,
        },
    )

    with pytest.raises(InfinoError) as exc:
        sdk.get_visualization("nope")
    assert exc.value.status_code() == 404


@pytest.mark.unit
def test_list_visualizations(sdk_with_mock_session, mock_response):
    """List endpoint returns an items envelope."""
    sdk = sdk_with_mock_session

    listing = {
        "items": [
            {"id": "a", "kind": "visualization", "attributes": {"title": "A"}},
            {"id": "b", "kind": "visualization", "attributes": {"title": "B"}},
        ]
    }
    sdk.session.request.return_value = mock_response(200, listing)

    result = sdk.list_visualizations()

    assert len(result["items"]) == 2
    assert result["items"][0]["id"] == "a"


@pytest.mark.unit
def test_delete_visualization(sdk_with_mock_session, mock_response):
    """Delete returns the standard ack body."""
    sdk = sdk_with_mock_session

    sdk.session.request.return_value = mock_response(200, {"deleted": True})

    result = sdk.delete_visualization("abc123")

    assert result["deleted"] is True


@pytest.mark.unit
def test_execute_visualization(sdk_with_mock_session, mock_response):
    """Execute returns plot-ready {columns, rows, metadata}."""
    sdk = sdk_with_mock_session

    payload = {
        "columns": [
            {"name": "currency", "type": "string"},
            {"name": "count", "type": "number"},
        ],
        "rows": [
            {"currency": "USD", "count": 142},
            {"currency": "EUR", "count": 89},
        ],
        "metadata": {
            "source_kind": "sql",
            "row_count": 2,
            "truncated": False,
            "took_ms": 23,
            "executed_query": "SELECT currency, COUNT(*) AS count FROM orders.rel GROUP BY currency",
        },
    }
    sdk.session.request.return_value = mock_response(200, payload)

    result = sdk.execute_visualization("abc123")

    assert result["metadata"]["row_count"] == 2
    assert result["columns"][0]["name"] == "currency"
    assert [row["currency"] for row in result["rows"]] == ["USD", "EUR"]
    assert [row["count"] for row in result["rows"]] == [142, 89]


@pytest.mark.unit
def test_execute_visualization_phase_1_rejects_filters(
    sdk_with_mock_session, mock_response
):
    """Phase 1 returns 400 if the caller supplies filters/time_range overrides;
    SDK does not pre-validate, the server is the source of truth."""
    sdk = sdk_with_mock_session

    sdk.session.request.return_value = mock_response(
        400,
        {
            "error": {
                "type": "ValidationError",
                "reason": "`filters` overrides are not yet supported in phase 1",
            },
            "status": 400,
        },
    )

    with pytest.raises(InfinoError) as exc:
        sdk.execute_visualization("abc123")
    assert exc.value.status_code() == 400


@pytest.mark.unit
def test_create_visualization_sends_post_with_json_body(
    sdk_with_mock_session, mock_response
):
    """Sanity check that the wire request shape matches the gateway's expectations."""
    sdk = sdk_with_mock_session

    sdk.session.request.return_value = mock_response(
        201, {"id": "abc", "kind": "visualization", "attributes": {}}
    )

    spec = {
        "title": "x",
        "source": {"kind": "sql", "index": "y", "sql": {"raw_query": "SELECT 1"}},
        "chart": {"type": "bar"},
    }
    sdk.create_visualization(spec)

    call = sdk.session.request.call_args
    assert call.kwargs["method"] == "POST"
    assert call.kwargs["url"].endswith("/visualizations")
    assert json.loads(call.kwargs["data"]) == spec


@pytest.mark.unit
def test_update_visualization_uses_patch(sdk_with_mock_session, mock_response):
    """update_visualization sends PATCH with the partial body unchanged."""
    sdk = sdk_with_mock_session

    sdk.session.request.return_value = mock_response(
        200, {"id": "abc", "kind": "visualization", "attributes": {"title": "renamed"}}
    )

    partial = {"title": "renamed", "source": {"sql": {"limit": 200}}}
    result = sdk.update_visualization("abc", partial)

    assert result["attributes"]["title"] == "renamed"
    call = sdk.session.request.call_args
    assert call.kwargs["method"] == "PATCH"
    assert call.kwargs["url"].endswith("/visualizations/abc")
    assert json.loads(call.kwargs["data"]) == partial


@pytest.mark.unit
def test_update_visualization_not_found(sdk_with_mock_session, mock_response):
    """PATCH on an unknown id returns 404."""
    sdk = sdk_with_mock_session

    sdk.session.request.return_value = mock_response(
        404,
        {
            "error": {"type": "NotFound", "reason": "visualization 'nope' not found"},
            "status": 404,
        },
    )

    with pytest.raises(InfinoError) as exc:
        sdk.update_visualization("nope", {"title": "x"})
    assert exc.value.status_code() == 404


@pytest.mark.unit
def test_list_visualizations_passes_pagination(sdk_with_mock_session, mock_response):
    """Pagination kwargs flow through to ?limit=&offset=."""
    sdk = sdk_with_mock_session
    sdk.session.request.return_value = mock_response(200, {"items": []})

    sdk.list_visualizations(limit=50, offset=100)

    call = sdk.session.request.call_args
    assert call.kwargs["params"] == {"limit": "50", "offset": "100"}


@pytest.mark.unit
def test_list_visualizations_no_pagination_kwargs(sdk_with_mock_session, mock_response):
    """Calling without kwargs sends no query params (server defaults apply)."""
    sdk = sdk_with_mock_session
    sdk.session.request.return_value = mock_response(200, {"items": []})

    sdk.list_visualizations()

    call = sdk.session.request.call_args
    assert call.kwargs.get("params") is None
