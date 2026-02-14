"""
Infino SDK - Query SQL Sources (Snowflake, BigQuery) Example

This example demonstrates querying SQL database sources via Infino:
- Using an existing Snowflake or BigQuery connection
- Running SQL queries via query_source(connection_id, dataset, query)
- Getting source metadata (schema, tables, columns)

For detailed request/response format documentation, see:
    docs/connectors.md#request-and-response-formats

Usage:
    export INFINO_ACCESS_KEY="your_key"
    export INFINO_SECRET_KEY="your_secret"
    export INFINO_ENDPOINT="https://api.infino.ws"
    # Set CONNECTION_ID and TABLE_NAME to your Snowflake/BigQuery connection and table
    python examples/connectors/query_sql_sources.py
"""

import logging
import os

from infino_sdk import InfinoError, InfinoSDK

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Use env vars to point to your SQL connection and table/dataset
CONNECTION_ID = os.getenv("SQL_CONNECTION_ID", "your_snowflake_or_bigquery_connection_id")
TABLE_NAME = os.getenv("SQL_TABLE_NAME", "sales_data")


# =============================================================================
# SQL QUERY EXAMPLES
# =============================================================================

def sql_select_limit(limit: int = 10) -> str:
    """Basic SELECT with LIMIT."""
    return f"SELECT * FROM {TABLE_NAME} LIMIT {limit}"


def sql_select_where(column: str, value: str, limit: int = 10) -> str:
    """SELECT with WHERE (use parameterized style in production)."""
    return f"SELECT * FROM {TABLE_NAME} WHERE {column} = '{value}' LIMIT {limit}"


def sql_aggregation(group_by: str, limit: int = 10) -> str:
    """GROUP BY with aggregation."""
    return f"SELECT {group_by}, COUNT(*) AS cnt FROM {TABLE_NAME} GROUP BY {group_by} LIMIT {limit}"


# =============================================================================
# MAIN
# =============================================================================


def main():
    """Run SQL source query demo."""
    access_key = os.getenv("INFINO_ACCESS_KEY", "your_access_key")
    secret_key = os.getenv("INFINO_SECRET_KEY", "your_secret_key")
    endpoint = os.getenv("INFINO_ENDPOINT", "https://api.infino.ws")

    sdk = InfinoSDK(access_key, secret_key, endpoint)

    try:
        # ---------------------------------------------------------------------
        # Step 1: Get source metadata (schema, columns)
        # ---------------------------------------------------------------------
        logger.info("[STEP 1] Getting source metadata for %s / %s...", CONNECTION_ID, TABLE_NAME)
        try:
            metadata = sdk.get_source_metadata(CONNECTION_ID, TABLE_NAME)
            logger.info("Metadata response keys: %s", list(metadata.keys()))
            # Metadata structure varies by source type
            # Common fields: columns, schema, mappings, etc.
            if "columns" in metadata:
                columns = metadata["columns"]
                logger.info("Columns found: %d", len(columns) if isinstance(columns, list) else "N/A")
                if isinstance(columns, list) and columns:
                    logger.info("  First column: %s", columns[0])
            if "schema" in metadata:
                logger.info("Schema: %s", metadata["schema"])
            if "mappings" in metadata:
                logger.info("Mappings available: %s", list(metadata["mappings"].keys()) if isinstance(metadata["mappings"], dict) else "N/A")
        except InfinoError as e:
            logger.warning("Could not get metadata: %s", e.message)
            logger.info("Continuing with query examples...")

        # ---------------------------------------------------------------------
        # Step 2: Run SQL queries (query is plain SQL string)
        # ---------------------------------------------------------------------
        logger.info("[STEP 2] Running SQL queries...")

        queries = [
            ("SELECT LIMIT 10", sql_select_limit(10)),
            ("GROUP BY aggregation", sql_aggregation("region", 5)),
        ]

        for name, sql in queries:
            try:
                results = sdk.query_source(CONNECTION_ID, TABLE_NAME, sql)
                # Snowflake/BigQuery response format:
                # {
                #   "execution_time": <ms>,
                #   "statement_type": "SELECT",
                #   "affected_rows": <count>,
                #   "error_message": "",
                #   "columns": [{"display_name": "...", "data_type": "..."}, ...],
                #   "rows": [[value1, value2, ...], ...]  # Array of arrays
                # }
                if isinstance(results, dict):
                    error_msg = results.get("error_message", "")
                    if error_msg:
                        logger.warning("  %s error: %s", name, error_msg)
                        continue
                    
                    columns = results.get("columns", [])
                    rows = results.get("rows", [])
                    execution_time = results.get("execution_time", 0)
                    affected_rows = results.get("affected_rows", len(rows))
                    
                    logger.info("  %s:", name)
                    logger.info("    Execution time: %d ms", execution_time)
                    logger.info("    Affected rows: %d", affected_rows)
                    if columns:
                        column_names = [col.get("display_name", col.get("name", "?")) for col in columns]
                        logger.info("    Columns: %s", ", ".join(column_names))
                    logger.info("    Rows returned: %d", len(rows))
                    
                    # Show first few rows as example
                    if rows:
                        logger.info("    First row: %s", rows[0] if len(rows) > 0 else "N/A")
                elif isinstance(results, list):
                    logger.info("  %s: %d rows (list format)", name, len(results))
                else:
                    logger.info("  %s: result type %s", name, type(results).__name__)
            except InfinoError as e:
                logger.warning("  %s failed: %s", name, e.message)

        logger.info("SQL source query demo completed.")

    except InfinoError as e:
        logger.error("Infino error: %s", e.message)
        raise
    finally:
        sdk.close()


if __name__ == "__main__":
    main()
