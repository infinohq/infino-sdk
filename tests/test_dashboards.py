"""
Tests for dashboard operations.

Exercises the v1 dashboard API:
    POST   /dashboards          — lenient create (server fills defaults)
    GET    /dashboards          — list
    GET    /dashboards/:id      — fetch one
    DELETE /dashboards/:id      — delete
"""

import json

import pytest

from infino_sdk.lib import InfinoError


@pytest.mark.unit
def test_create_dashboard_minimum_body(sdk_with_mock_session, mock_response):
    """Caller sends a minimum body; server returns the full envelope with
    defaults filled (auto layout, options, ids)."""
    sdk = sdk_with_mock_session

    server_envelope = {
        "id": "dash-abc",
        "kind": "dashboard",
        "created_at": "2026-05-14T09:53:23Z",
        "updated_at": "2026-05-14T09:53:23Z",
        "attributes": {
            "schema_version": 1,
            "id": "dash-abc",
            "title": "Revenue overview",
            "panels": [
                {
                    "kind": "visualization",
                    "id": "panel_0",
                    "layout": {"x": 0, "y": 0, "w": 24, "h": 15},
                    "title_override": None,
                    "viz_id": "viz-a",
                },
                {
                    "kind": "visualization",
                    "id": "panel_1",
                    "layout": {"x": 24, "y": 0, "w": 24, "h": 15},
                    "title_override": None,
                    "viz_id": "viz-b",
                },
            ],
            "options": {
                "use_margins": True,
                "hide_panel_titles": False,
                "refresh_interval": None,
            },
            "filters": [],
            "time_range": None,
            "chat_thread_id": None,
            "tags": [],
        },
    }
    sdk.session.request.return_value = mock_response(201, server_envelope)

    result = sdk.create_dashboard(
        {
            "title": "Revenue overview",
            "panels": [{"viz_id": "viz-a"}, {"viz_id": "viz-b"}],
        }
    )

    assert result["id"] == "dash-abc"
    assert len(result["attributes"]["panels"]) == 2
    # Server filled the per-panel auto-layout
    assert result["attributes"]["panels"][0]["layout"]["x"] == 0
    assert result["attributes"]["panels"][1]["layout"]["x"] == 24
    # Server filled dashboard-level options
    assert result["attributes"]["options"]["use_margins"] is True


@pytest.mark.unit
def test_create_dashboard_missing_title_returns_400(
    sdk_with_mock_session, mock_response
):
    """Server rejects bodies missing the required `title` field."""
    sdk = sdk_with_mock_session

    sdk.session.request.return_value = mock_response(
        400,
        {"error": {"type": "ValidationError", "reason": "`title` is required"}, "status": 400},
    )

    with pytest.raises(InfinoError) as exc:
        sdk.create_dashboard({"panels": []})
    assert exc.value.status_code() == 400


@pytest.mark.unit
def test_create_dashboard_panel_missing_viz_id(sdk_with_mock_session, mock_response):
    """Visualization panels without a `viz_id` are rejected at the server."""
    sdk = sdk_with_mock_session

    sdk.session.request.return_value = mock_response(
        400,
        {
            "error": {
                "type": "ValidationError",
                "reason": "panel[0] of kind `visualization` requires `viz_id`",
            },
            "status": 400,
        },
    )

    with pytest.raises(InfinoError) as exc:
        sdk.create_dashboard({"title": "x", "panels": [{}]})
    assert exc.value.status_code() == 400


@pytest.mark.unit
def test_get_dashboard(sdk_with_mock_session, mock_response):
    """Fetch a dashboard by id."""
    sdk = sdk_with_mock_session

    envelope = {
        "id": "dash-abc",
        "kind": "dashboard",
        "created_at": "2026-05-14T09:53:23Z",
        "updated_at": "2026-05-14T09:53:23Z",
        "attributes": {"title": "Revenue overview", "panels": []},
    }
    sdk.session.request.return_value = mock_response(200, envelope)

    result = sdk.get_dashboard("dash-abc")

    assert result["id"] == "dash-abc"
    assert result["attributes"]["title"] == "Revenue overview"


@pytest.mark.unit
def test_get_dashboard_not_found(sdk_with_mock_session, mock_response):
    """Unknown ids return 404."""
    sdk = sdk_with_mock_session

    sdk.session.request.return_value = mock_response(
        404,
        {
            "error": {"type": "NotFound", "reason": "dashboard 'nope' not found"},
            "status": 404,
        },
    )

    with pytest.raises(InfinoError) as exc:
        sdk.get_dashboard("nope")
    assert exc.value.status_code() == 404


@pytest.mark.unit
def test_list_dashboards(sdk_with_mock_session, mock_response):
    """List endpoint returns an items envelope."""
    sdk = sdk_with_mock_session

    listing = {
        "items": [
            {"id": "a", "kind": "dashboard", "attributes": {"title": "A"}},
            {"id": "b", "kind": "dashboard", "attributes": {"title": "B"}},
        ]
    }
    sdk.session.request.return_value = mock_response(200, listing)

    result = sdk.list_dashboards()

    assert len(result["items"]) == 2
    assert result["items"][0]["id"] == "a"


@pytest.mark.unit
def test_delete_dashboard(sdk_with_mock_session, mock_response):
    """Delete returns the standard ack body."""
    sdk = sdk_with_mock_session

    sdk.session.request.return_value = mock_response(200, {"deleted": True})

    result = sdk.delete_dashboard("dash-abc")

    assert result["deleted"] is True


@pytest.mark.unit
def test_create_dashboard_sends_post_with_json_body(
    sdk_with_mock_session, mock_response
):
    """Sanity check that the wire request shape matches the gateway's expectations."""
    sdk = sdk_with_mock_session

    sdk.session.request.return_value = mock_response(
        201, {"id": "d", "kind": "dashboard", "attributes": {}}
    )

    spec = {
        "title": "x",
        "panels": [{"viz_id": "v1"}, {"viz_id": "v2"}],
    }
    sdk.create_dashboard(spec)

    call = sdk.session.request.call_args
    assert call.kwargs["method"] == "POST"
    assert call.kwargs["url"].endswith("/dashboards")
    assert json.loads(call.kwargs["data"]) == spec


@pytest.mark.unit
def test_update_dashboard_uses_patch(sdk_with_mock_session, mock_response):
    """update_dashboard sends PATCH with the partial body unchanged."""
    sdk = sdk_with_mock_session

    sdk.session.request.return_value = mock_response(
        200, {"id": "d", "kind": "dashboard", "attributes": {"title": "renamed"}}
    )

    partial = {"title": "renamed"}
    result = sdk.update_dashboard("d", partial)

    assert result["attributes"]["title"] == "renamed"
    call = sdk.session.request.call_args
    assert call.kwargs["method"] == "PATCH"
    assert call.kwargs["url"].endswith("/dashboards/d")
    assert json.loads(call.kwargs["data"]) == partial


@pytest.mark.unit
def test_list_dashboards_passes_pagination(sdk_with_mock_session, mock_response):
    """Pagination kwargs flow through to ?limit=&offset=."""
    sdk = sdk_with_mock_session
    sdk.session.request.return_value = mock_response(200, {"items": []})

    sdk.list_dashboards(limit=10, offset=20)

    call = sdk.session.request.call_args
    assert call.kwargs["params"] == {"limit": "10", "offset": "20"}


@pytest.mark.unit
def test_execute_dashboard_fans_out_panels(sdk_with_mock_session, mock_response):
    """execute_dashboard fetches the dashboard, then per-panel viz + data."""
    sdk = sdk_with_mock_session

    # The SDK will make 1 + 2N HTTP calls — sequence the mocked responses to
    # match. Order: get_dashboard, then per-panel (get_viz, execute_viz) × 2.
    # ThreadPoolExecutor may reorder per-panel calls, but each panel's
    # (get_viz, execute_viz) pair is consistent so any ordering works.
    dash_envelope = {
        "id": "dash-x",
        "kind": "dashboard",
        "attributes": {
            "title": "Test",
            "panels": [
                {"id": "p0", "kind": "visualization",
                 "viz_id": "viz-a", "layout": {"x": 0, "y": 0, "w": 24, "h": 12},
                 "title_override": None},
                {"id": "p1", "kind": "visualization",
                 "viz_id": "viz-b", "layout": {"x": 24, "y": 0, "w": 24, "h": 12},
                 "title_override": None},
            ],
        },
    }
    viz_a = {"id": "viz-a", "kind": "visualization", "attributes": {"title": "A", "chart": {"type": "bar"}}}
    viz_b = {"id": "viz-b", "kind": "visualization", "attributes": {"title": "B", "chart": {"type": "pie"}}}
    data_a = {"columns": [{"name": "x", "type": "string"}], "rows": [{"x": "alpha"}],
              "metadata": {"row_count": 1}}
    data_b = {"columns": [{"name": "y", "type": "number"}], "rows": [{"y": 42}],
              "metadata": {"row_count": 1}}

    # Route each mocked request based on URL so thread ordering doesn't matter.
    def fake_request(*args, **kwargs):
        url = kwargs.get("url", "")
        if url.endswith("/dashboards/dash-x"):
            return mock_response(200, dash_envelope)
        if url.endswith("/visualizations/viz-a/data"):
            return mock_response(200, data_a)
        if url.endswith("/visualizations/viz-b/data"):
            return mock_response(200, data_b)
        if url.endswith("/visualizations/viz-a"):
            return mock_response(200, viz_a)
        if url.endswith("/visualizations/viz-b"):
            return mock_response(200, viz_b)
        return mock_response(404, {"error": "unexpected url: " + url})

    sdk.session.request.side_effect = fake_request

    panels = sdk.execute_dashboard("dash-x")

    assert len(panels) == 2
    # Ordering preserved from dashboard.panels
    assert [p["id"] for p in panels] == ["p0", "p1"]
    # Each panel has viz, data, layout, no error
    for p in panels:
        assert p["kind"] == "visualization"
        assert p["viz"] is not None
        assert p["data"] is not None
        assert p["error"] is None
        assert p["layout"] is not None
    assert panels[0]["viz"]["title"] == "A"
    assert panels[1]["viz"]["title"] == "B"


@pytest.mark.unit
def test_execute_dashboard_isolates_per_panel_errors(
    sdk_with_mock_session, mock_response
):
    """A 4xx on one panel doesn't fail the whole call; other panels return OK."""
    sdk = sdk_with_mock_session

    dash_envelope = {
        "id": "dash-x", "kind": "dashboard",
        "attributes": {"title": "T", "panels": [
            {"id": "p0", "kind": "visualization", "viz_id": "viz-ok",
             "layout": {"x": 0, "y": 0, "w": 48, "h": 12}, "title_override": None},
            {"id": "p1", "kind": "visualization", "viz_id": "viz-bad",
             "layout": {"x": 0, "y": 12, "w": 48, "h": 12}, "title_override": None},
        ]},
    }
    good_viz = {"id": "viz-ok", "kind": "visualization",
                "attributes": {"title": "OK", "chart": {"type": "bar"}}}
    good_data = {"columns": [], "rows": [], "metadata": {"row_count": 0}}

    def fake_request(*args, **kwargs):
        url = kwargs.get("url", "")
        if url.endswith("/dashboards/dash-x"):
            return mock_response(200, dash_envelope)
        if url.endswith("/visualizations/viz-ok"):
            return mock_response(200, good_viz)
        if url.endswith("/visualizations/viz-ok/data"):
            return mock_response(200, good_data)
        if "viz-bad" in url:
            return mock_response(
                404,
                {"error": {"type": "NotFound", "reason": "viz-bad not found"}, "status": 404},
            )
        return mock_response(500, {"error": "unexpected"})

    sdk.session.request.side_effect = fake_request

    panels = sdk.execute_dashboard("dash-x")

    assert len(panels) == 2
    ok, bad = panels
    assert ok["error"] is None and ok["viz"] and ok["data"]
    assert bad["error"] is not None
    assert bad["error"]["status"] == 404
    assert bad["viz"] is None and bad["data"] is None


@pytest.mark.unit
def test_execute_dashboard_handles_non_viz_panels(sdk_with_mock_session, mock_response):
    """Markdown and divider panels are returned without viz/data."""
    sdk = sdk_with_mock_session

    dash = {
        "id": "d", "kind": "dashboard",
        "attributes": {"title": "T", "panels": [
            {"id": "md0", "kind": "markdown", "content": "# Hello",
             "layout": {"x": 0, "y": 0, "w": 48, "h": 4}, "title_override": None},
            {"id": "dv0", "kind": "divider", "label": "Section",
             "layout": {"x": 0, "y": 4, "w": 48, "h": 2}, "title_override": None},
        ]},
    }
    sdk.session.request.return_value = mock_response(200, dash)

    panels = sdk.execute_dashboard("d")

    assert len(panels) == 2
    assert panels[0]["kind"] == "markdown"
    assert panels[0]["content"] == "# Hello"
    assert panels[0]["viz"] is None
    assert panels[1]["kind"] == "divider"
    assert panels[1]["label"] == "Section"
