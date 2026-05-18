"""
Dashboard HTML renderer.

Reads a dashboard, executes every panel in parallel via
:meth:`InfinoSDK.execute_dashboard`, then composes one HTML page that
honors each panel's stored ``layout: {x, y, w, h}`` using CSS Grid.

The plot library choice (ECharts) is yours — the SDK returns
``{columns, rows, metadata}`` and stays out of the render decision.
The same data fits matplotlib / plotly / altair / anything else.
"""

from __future__ import annotations

import html
import json
from typing import Any

# Pixels per row unit in the dashboard grid (matches OSD-style 48-column grid).
ROW_PX = 22
GAP_PX = 8


def _grid_style(layout: dict[str, int]) -> str:
    """Translate a panel ``layout: {x, y, w, h}`` into CSS Grid placement."""
    return (
        f"grid-column: {layout['x'] + 1} / span {layout['w']}; "
        f"grid-row: {layout['y'] + 1} / span {layout['h']};"
    )


def _render_echarts_panel(
    panel_id: str, spec: dict[str, Any], style: str
) -> tuple[str, str]:
    """Return (panel_div_html, init_script) for an ECharts-backed panel."""
    div = (
        f'<div class="panel" style="{style}">'
        f'<div id="chart_{panel_id}" class="chart"></div></div>'
    )
    script = (
        f"echarts.init(document.getElementById('chart_{panel_id}'))"
        f".setOption({json.dumps(spec['option'])});"
    )
    return div, script


def _render_table_panel(spec: dict[str, Any], style: str) -> str:
    cols = [c["name"] for c in spec["columns"]]
    head = "".join(f"<th>{html.escape(str(c))}</th>" for c in cols)
    body_rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{html.escape(str(r.get(c) if r.get(c) is not None else ''))}</td>"
            for c in cols
        )
        + "</tr>"
        for r in spec["rows"][:50]
    )
    return (
        f'<div class="panel table-panel" style="{style}">'
        f'<div class="panel-title">{html.escape(spec["title"])}</div>'
        f'<div class="table-scroll"><table><thead><tr>{head}</tr></thead>'
        f"<tbody>{body_rows}</tbody></table></div></div>"
    )


def _render_metric_panel(spec: dict[str, Any], style: str) -> str:
    fmt = spec.get("formatting") or {}
    prefix = fmt.get("prefix") or ""
    suffix = fmt.get("suffix") or ""
    value = spec.get("value")
    return (
        f'<div class="panel metric-panel" style="{style}">'
        f'<div class="panel-title">{html.escape(spec["title"])}</div>'
        f'<div class="metric-value">'
        f"{html.escape(prefix)}{html.escape(str(value))}{html.escape(suffix)}"
        f"</div></div>"
    )


def _render_error_panel(panel: dict[str, Any]) -> str:
    layout = panel["layout"]
    err = panel["error"]
    return (
        f'<div class="panel error-panel" style="{_grid_style(layout)}">'
        f'<div class="panel-title">Error</div>'
        f'<div class="error-body">{html.escape(str(err.get("status")))}: '
        f'{html.escape(str(err.get("message"))[:200])}</div></div>'
    )


def build_dashboard_html(sdk, dashboard_id: str) -> str:
    """
    Read a dashboard, execute every panel in parallel via
    :meth:`InfinoSDK.execute_dashboard`, then build a single HTML page
    that lays panels out via CSS Grid honoring each panel's stored
    ``layout: {x, y, w, h}``.

    Per-panel errors are isolated — one bad panel renders as an inline
    error placeholder; the rest still render.
    """
    title = sdk.get_dashboard(dashboard_id)["attributes"]["title"]
    panels = sdk.execute_dashboard(dashboard_id)

    body_parts: list[str] = []
    init_scripts: list[str] = []

    for panel in panels:
        if panel.get("kind") != "visualization":
            continue
        if panel.get("error"):
            body_parts.append(_render_error_panel(panel))
            continue

        spec = sdk.to_echarts_option(panel["viz"], panel["data"])
        style = _grid_style(panel["layout"])

        if spec["kind"] == "echarts":
            div, script = _render_echarts_panel(panel["id"], spec, style)
            body_parts.append(div)
            init_scripts.append(script)
        elif spec["kind"] == "table":
            body_parts.append(_render_table_panel(spec, style))
        elif spec["kind"] == "metric":
            body_parts.append(_render_metric_panel(spec, style))

    return f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>{html.escape(title)}</title>
<script src="https://assets.pyecharts.org/assets/v6/echarts.min.js"></script>
<style>
  body {{ margin: 0; font-family: -apple-system, system-ui, sans-serif; background: #f6f7f8; }}
  h1 {{ padding: 16px 24px; margin: 0; background: white; border-bottom: 1px solid #e5e7eb; }}
  .dashboard {{
    display: grid;
    grid-template-columns: repeat(48, 1fr);
    grid-auto-rows: {ROW_PX}px;
    gap: {GAP_PX}px;
    padding: {GAP_PX}px;
  }}
  .panel {{
    background: white;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    overflow: hidden;
    box-shadow: 0 1px 2px rgba(0,0,0,0.04);
  }}
  .chart {{ width: 100%; height: 100%; }}
  .panel-title {{ padding: 8px 12px; font-weight: 600; border-bottom: 1px solid #f0f0f0; font-size: 14px; }}
  .table-scroll {{ overflow: auto; height: calc(100% - 36px); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th, td {{ padding: 6px 10px; border-bottom: 1px solid #f0f0f0; text-align: left; }}
  th {{ background: #fafafa; position: sticky; top: 0; }}
  .metric-panel {{ display: flex; flex-direction: column; }}
  .metric-value {{ flex: 1; display: flex; align-items: center; justify-content: center;
                   font-size: 36px; font-weight: 600; color: #1f2937; }}
  .error-panel {{ background: #fef2f2; }}
  .error-body {{ padding: 8px 12px; color: #991b1b; font-size: 12px; word-break: break-word; }}
</style>
</head><body>
<h1>{html.escape(title)}</h1>
<div class="dashboard">
{''.join(body_parts)}
</div>
<script>
{chr(10).join(init_scripts)}
window.addEventListener('resize', function() {{
  document.querySelectorAll('.chart').forEach(function(el) {{
    var inst = echarts.getInstanceByDom(el);
    if (inst) inst.resize();
  }});
}});
</script>
</body></html>
"""
