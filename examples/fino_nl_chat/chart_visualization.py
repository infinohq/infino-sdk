"""
Infino SDK - Chart Visualization Example

This example demonstrates how to use the Infino SDK with streaming mode
to receive ECharts chart configurations and render them in a browser.

The chart configuration received in the streaming response is a standard
ECharts config object that can be directly passed to ECharts for rendering.

Usage:
    export INFINO_ACCESS_KEY="your_key"
    export INFINO_SECRET_KEY="your_secret"
    python -m examples.fino_nl_chat.chart_visualization
"""

from __future__ import annotations

import asyncio
import html
import json
import tempfile
import time
import uuid
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from websockets.exceptions import ConnectionClosed

from infino_sdk import InfinoError, InfinoSDK

from .common import (ACCESS_KEY, CONNECTION_TIMEOUT, ENDPOINT, SECRET_KEY,
                     StreamingResponse, create_thread, generate_bulk_payload,
                     handle_streaming_response, setup_logging,
                     validate_credentials)

# =============================================================================
# SETUP
# =============================================================================

logger = setup_logging()

DATASET_NAME = "chart_demo_orders"

# =============================================================================
# SAMPLE DATA - Orders with timestamps for time-series visualization
# =============================================================================


def generate_sample_orders() -> list[dict[str, Any]]:
    """
    Generate sample order data with timestamps spread over the last 30 days.

    Returns:
        List of order dictionaries with id, customer, product, amount,
        status, and timestamp fields.
    """
    products = [
        ("Laptop", 999.99),
        ("Headphones", 79.99),
        ("Keyboard", 129.99),
        ("Mouse", 49.99),
        ("Monitor", 299.99),
        ("USB Cable", 12.99),
        ("Webcam", 89.99),
        ("Desk Lamp", 39.99),
    ]
    customers = [
        "Alice Johnson",
        "Bob Smith",
        "Carol Williams",
        "David Brown",
        "Eve Davis",
        "Frank Miller",
        "Grace Wilson",
        "Henry Moore",
    ]
    statuses = ["completed", "completed", "completed", "pending", "shipped"]

    orders = []
    order_id = 1

    # Generate orders spread across the last 30 days
    # More orders on recent days for a realistic trend
    base_date = datetime.utcnow()

    for days_ago in range(30, -1, -1):
        # More orders as we get closer to today (growth trend)
        num_orders = max(1, (31 - days_ago) // 5) + (1 if days_ago % 3 == 0 else 0)

        for _ in range(num_orders):
            product_name, product_price = products[order_id % len(products)]
            customer = customers[order_id % len(customers)]
            status = statuses[order_id % len(statuses)]

            # Random hour within the day
            hour_offset = (order_id * 7) % 24
            order_time = base_date - timedelta(days=days_ago, hours=hour_offset)

            orders.append(
                {
                    "id": order_id,
                    "customer_name": customer,
                    "product_name": product_name,
                    "amount": product_price * ((order_id % 3) + 1),  # Vary quantity
                    "status": status,
                    "timestamp": order_time.isoformat() + "Z",
                    "order_date": order_time.strftime("%Y-%m-%d"),
                }
            )
            order_id += 1

    return orders


SAMPLE_ORDERS = generate_sample_orders()


# =============================================================================
# ECHART HTML RENDERING
# =============================================================================


def create_echart_html(chart_config: dict[str, Any], title: str = "Chart") -> str:
    """
    Create an HTML page that renders an ECharts chart.

    Args:
        chart_config: The ECharts configuration object received from Fino.
        title: Page title for the HTML document.

    Returns:
        Complete HTML string with embedded ECharts.
    """
    # Escape the JSON for safe embedding in HTML
    chart_json = json.dumps(chart_config, indent=2)

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1 {{
            color: #fff;
            text-align: center;
            margin-bottom: 20px;
            font-weight: 300;
            font-size: 24px;
        }}
        .subtitle {{
            color: #8892b0;
            text-align: center;
            margin-bottom: 30px;
            font-size: 14px;
        }}
        #chart {{
            width: 100%;
            height: 500px;
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
            padding: 20px;
        }}
        .info-panel {{
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 15px 20px;
            margin-top: 20px;
            color: #8892b0;
            font-size: 13px;
        }}
        .info-panel code {{
            background: rgba(255, 255, 255, 0.1);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Fira Code', monospace;
        }}
        details {{
            margin-top: 20px;
        }}
        summary {{
            color: #64ffda;
            cursor: pointer;
            font-size: 14px;
        }}
        pre {{
            background: #1a1a2e;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            margin-top: 10px;
            font-size: 12px;
            color: #ccc;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Infino SDK - Chart Visualization</h1>
        <p class="subtitle">Generated from natural language query using Fino AI</p>

        <div id="chart"></div>

        <div class="info-panel">
            This chart was generated by asking Fino AI: <code>"Show me orders over time"</code><br>
            The visualization agent automatically analyzed the data and created an appropriate chart configuration.
        </div>

        <details>
            <summary>View ECharts Configuration</summary>
            <pre>{html.escape(chart_json)}</pre>
        </details>
    </div>

    <script>
        // Initialize ECharts
        const chartDom = document.getElementById('chart');
        const myChart = echarts.init(chartDom);

        // Chart configuration from Fino AI response
        const option = {chart_json};

        // Set the chart options
        myChart.setOption(option);

        // Handle window resize
        window.addEventListener('resize', function() {{
            myChart.resize();
        }});
    </script>
</body>
</html>"""

    return html_template


def render_chart_in_browser(
    chart_config: dict[str, Any],
    title: str = "Orders Over Time",
) -> str | None:
    """
    Render an ECharts chart configuration in the default web browser.

    Args:
        chart_config: The ECharts configuration object.
        title: Title for the chart page.

    Returns:
        Path to the generated HTML file, or None if rendering failed.
    """
    if not chart_config:
        logger.warning("No chart configuration provided")
        return None

    html_content = create_echart_html(chart_config, title)

    # Create a temporary HTML file
    temp_dir = tempfile.gettempdir()
    html_filename = f"infino_chart_{uuid.uuid4().hex[:8]}.html"
    html_path = Path(temp_dir) / html_filename

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    logger.info("Chart HTML saved to: %s", html_path)

    # Open in default browser
    file_url = f"file://{html_path}"
    webbrowser.open(file_url)
    logger.info("Opened chart in browser")

    return str(html_path)


# =============================================================================
# SETUP AND CLEANUP
# =============================================================================


def setup_dataset(sdk: InfinoSDK) -> None:
    """
    Set up the demo dataset with sample order data.

    Args:
        sdk: Initialized InfinoSDK instance.
    """
    # Clean up any existing dataset
    try:
        sdk.delete_dataset(DATASET_NAME)
        time.sleep(1)
    except InfinoError:
        pass

    sdk.create_dataset(DATASET_NAME)
    logger.info("Created dataset: %s", DATASET_NAME)

    payload = generate_bulk_payload(SAMPLE_ORDERS)
    sdk.upload_json_to_dataset(DATASET_NAME, payload)
    logger.info("Ingested %d sample orders", len(SAMPLE_ORDERS))

    # Allow time for indexing
    time.sleep(3)


def cleanup_dataset(sdk: InfinoSDK) -> None:
    """
    Clean up the demo dataset.

    Args:
        sdk: Initialized InfinoSDK instance.
    """
    try:
        sdk.delete_dataset(DATASET_NAME)
        logger.info("Deleted dataset: %s", DATASET_NAME)
    except InfinoError as e:
        error_str = str(e).lower()
        if "not_found" in error_str or "404" in error_str:
            logger.info("Dataset already deleted or not found")
        else:
            logger.warning("Could not delete dataset: %s", e)
    except (OSError, ValueError, RuntimeError) as e:
        logger.warning("Cleanup error: %s", e)


# =============================================================================
# MAIN
# =============================================================================


async def main() -> None:
    """
    Main entry point demonstrating chart visualization with streaming.

    Steps:
        1. Setup sample orders data (with timestamps)
        2. Create streaming thread
        3. Ask "show me orders over time"
        4. Receive chart configuration via streaming
        5. Render chart using ECharts in browser
        6. Cleanup
    """
    logger.info("=" * 70)
    logger.info("Infino SDK - Chart Visualization Example")
    logger.info("=" * 70)

    validate_credentials(logger)

    sdk = InfinoSDK(ACCESS_KEY, SECRET_KEY, ENDPOINT)
    ws = None
    dataset_created = False

    try:
        # Step 1: Setup sample orders data
        logger.info("[STEP 1] Setting up sample orders data...")
        setup_dataset(sdk)
        dataset_created = True

        # Step 2: Create streaming thread
        logger.info("[STEP 2] Creating thread with streaming=true...")
        sources = [{"index_name": DATASET_NAME, "connection_id": "infino"}]
        thread_id = create_thread(
            sdk, "Chart Demo", streaming=True, sources=sources
        )

        # Step 3: Connect to WebSocket
        logger.info("[STEP 3] Connecting to WebSocket...")
        ws_headers = {
            "x-infino-thread-id": thread_id,
            "x-infino-client-id": f"chart-{uuid.uuid4().hex[:8]}",
        }
        ws = await asyncio.wait_for(
            sdk.websocket_connect("/_conversation/ws", headers=ws_headers),
            timeout=CONNECTION_TIMEOUT,
        )
        logger.info("Connected!")

        # Step 4: Ask about orders over time (will generate a chart)
        logger.info("[STEP 4] Asking for orders over time visualization...")
        logger.info("Query: 'Show me orders over time'")
        logger.info("-" * 70)

        response: StreamingResponse = await handle_streaming_response(
            ws, "Show me orders over time"
        )

        # Step 5: Render chart if received
        logger.info("[STEP 5] Rendering chart...")
        if response.chart:
            logger.info("Received ECharts configuration!")
            chart_path = render_chart_in_browser(
                response.chart, "Orders Over Time - Infino Demo"
            )
            if chart_path:
                logger.info("Chart rendered successfully!")
                logger.info("HTML file: %s", chart_path)
        else:
            logger.warning("No chart was generated in the response.")
            logger.info("Summary received: %s", response.summary[:200] if response.summary else "None")

        # Optional: Ask a follow-up question
        await asyncio.sleep(2)

        logger.info("-" * 70)
        logger.info("[FOLLOW-UP] Asking about revenue trends...")

        response2: StreamingResponse = await handle_streaming_response(
            ws, "What's the total revenue by product?"
        )

        if response2.chart:
            logger.info("Received follow-up chart!")
            render_chart_in_browser(
                response2.chart, "Revenue by Product - Infino Demo"
            )

        logger.info("=" * 70)
        logger.info("Example complete!")
        logger.info("=" * 70)

    except asyncio.TimeoutError:
        logger.error("Timeout waiting for connection")
    except ConnectionClosed as e:
        logger.error("WebSocket connection closed: %s", e)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except (InfinoError, OSError, ValueError, RuntimeError) as e:
        logger.error("Error: %s: %s", type(e).__name__, e)
    finally:
        # Close WebSocket
        if ws:
            try:
                await ws.close()
            except (OSError, RuntimeError):
                pass  # Ignore errors during cleanup

        # Delete dataset
        logger.info("[CLEANUP] Deleting dataset...")
        if dataset_created:
            cleanup_dataset(sdk)

        sdk.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Exiting...")
