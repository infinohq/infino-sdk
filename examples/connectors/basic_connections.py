"""
Infino SDK - Connection Lifecycle Example

This example demonstrates the full connection lifecycle for external data sources:
- Discovering available data source types (get_sources)
- Creating connections for Elasticsearch, Snowflake, and BigQuery
- Listing and inspecting active connections
- Updating connection configuration
- Deleting connections

Usage:
    export INFINO_ACCESS_KEY="your_key"
    export INFINO_SECRET_KEY="your_secret"
    export INFINO_ENDPOINT="https://api.infino.ws"
    python examples/connectors/basic_connections.py

Note: Creating connections requires valid credentials for your external sources.
      Use placeholder configs below and replace with your own to test against
      real Elasticsearch, Snowflake, or BigQuery instances.
"""

import logging
import os

from infino_sdk import InfinoError, InfinoSDK

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# =============================================================================
# PLACEHOLDER CONFIGS (replace with your own for real connections)
# =============================================================================

def elasticsearch_config():
    """Elasticsearch/OpenSearch connection config."""
    return {
        "config": {
            "name": "Demo ES Cluster",
            "host": os.getenv("ES_HOST", "https://localhost:9200"),
            "username": os.getenv("ES_USERNAME", "elastic"),
            "password": os.getenv("ES_PASSWORD", "changeme"),
            "ssl_verify": os.getenv("ES_SSL_VERIFY", "true").lower() == "true",
        },
    }


def snowflake_config():
    """Snowflake connection config."""
    config = {
        "name": "Demo Snowflake Warehouse",
        "account": os.getenv("SNOWFLAKE_ACCOUNT", "your-account.snowflakecomputing.com"),
        "warehouse": os.getenv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH"),
        "database": os.getenv("SNOWFLAKE_DATABASE", "PRODUCTION_DB"),
        "schema": os.getenv("SNOWFLAKE_SCHEMA", "PUBLIC"),
    }
    
    # Support PAT (Programmatic Access Token) authentication if provided
    pat_token = os.getenv("SNOWFLAKE_PAT")
    if pat_token:
        config["pat_token"] = pat_token
        role = os.getenv("SNOWFLAKE_ROLE")
        if role:
            config["role"] = role
    else:
        # Fall back to username/password if PAT not provided
        config["username"] = os.getenv("SNOWFLAKE_USERNAME", "user")
        config["password"] = os.getenv("SNOWFLAKE_PASSWORD", "secret")
        role = os.getenv("SNOWFLAKE_ROLE")
        if role:
            config["role"] = role
    
    return {"config": config}


def bigquery_config():
    """BigQuery connection config."""
    import json
    
    # Service account key can be provided as JSON string or file path
    service_account_key = os.getenv("BIGQUERY_SERVICE_ACCOUNT_KEY")
    if not service_account_key:
        # If not provided, use a placeholder structure
        service_account_key = json.dumps({
            "type": "service_account",
            "project_id": "your-project-id",
            "private_key_id": "key-id",
            "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
            "client_email": "service@your-project.iam.gserviceaccount.com",
            "client_id": "client-id",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
        })
    else:
        # If it's a file path, read it
        if os.path.exists(service_account_key):
            with open(service_account_key, 'r') as f:
                service_account_key = f.read()
    
    return {
        "config": {
            "name": "Demo BigQuery Warehouse",
            "dataset_ids": os.getenv("BIGQUERY_DATASET_IDS", "dataset1, dataset2"),
            "service_account_key": service_account_key,
        },
    }


# =============================================================================
# MAIN
# =============================================================================


def main():
    """Run connection lifecycle demo."""
    access_key = os.getenv("INFINO_ACCESS_KEY", "your_access_key")
    secret_key = os.getenv("INFINO_SECRET_KEY", "your_secret_key")
    endpoint = os.getenv("INFINO_ENDPOINT", "https://api.infino.ws")

    sdk = InfinoSDK(access_key, secret_key, endpoint)
    created_connection_ids = []

    try:
        # ---------------------------------------------------------------------
        # Step 1: Discover available data source types
        # ---------------------------------------------------------------------
        logger.info("[STEP 1] Discovering available data source types...")
        sources = sdk.get_sources()
        logger.info("Available sources: %d", len(sources))
        for src in sources:
            name = src.get("name") or src.get("id") or "unknown"
            desc = src.get("description", "")
            logger.info("  - %s: %s", name, desc[:60] + "..." if len(desc) > 60 else desc)

        # ---------------------------------------------------------------------
        # Step 2: Create connections (one per source type you want to demo)
        # ---------------------------------------------------------------------
        logger.info("[STEP 2] Creating connections (using placeholder configs)...")

        for source_type, config_fn in [
            ("elasticsearch", elasticsearch_config),
            ("snowflake", snowflake_config),
            ("bigquery", bigquery_config),
        ]:
            config = config_fn()
            try:
                conn = sdk.create_connection(source_type, config)
                cid = conn.get("id") or conn.get("connection_id")
                if cid:
                    created_connection_ids.append(cid)
                    logger.info("  Created %s connection: %s", source_type, cid)
                else:
                    logger.warning("  Created %s connection but no id in response: %s", source_type, conn)
            except InfinoError as e:
                logger.warning(
                    "  Could not create %s connection (expected if no real backend): %s",
                    source_type,
                    e.message,
                )

        # ---------------------------------------------------------------------
        # Step 3: List active connections
        # ---------------------------------------------------------------------
        logger.info("[STEP 3] Listing active connections...")
        connections = sdk.get_connections()
        logger.info("Active connections: %d", len(connections))
        for conn in connections:
            logger.info(
                "  id=%s type=%s status=%s",
                conn.get("id"),
                conn.get("type"),
                conn.get("status"),
            )

        # ---------------------------------------------------------------------
        # Step 4: Get connection status for each created connection
        # ---------------------------------------------------------------------
        logger.info("[STEP 4] Getting connection status...")
        for cid in created_connection_ids:
            try:
                status = sdk.get_connection(cid)
                logger.info("  %s: status=%s", cid, status.get("status"))

                # Step 5: Update connection (e.g. rename)
                new_name = (status.get("config") or {}).get("name") or status.get("name") or ""
                if not new_name:
                    new_name = "Updated " + cid[:8]
                update_config = {"name": new_name}
                sdk.update_connection(cid, update_config)
                logger.info("  Updated connection %s name", cid)
            except InfinoError as e:
                logger.warning("  Could not get/update %s: %s", cid, e.message)

        logger.info("Connection lifecycle demo completed.")

    except InfinoError as e:
        logger.error("Infino error: %s", e.message)
        if e.status_code():
            logger.error("Status code: %s", e.status_code())
        raise
    finally:
        # ---------------------------------------------------------------------
        # Cleanup: delete created connections
        # ---------------------------------------------------------------------
        for cid in created_connection_ids:
            try:
                sdk.delete_connection(cid)
                logger.info("Deleted connection: %s", cid)
            except InfinoError as e:
                logger.warning("Could not delete %s: %s", cid, e.message)
        sdk.close()


if __name__ == "__main__":
    main()
