"""
Bulk Ingestion with Size-Based Chunking

This example demonstrates:
- Batching documents for bulk ingestion with size limits
- Calculating payload overhead for accurate size tracking
- Automatic chunking when approaching the maximum payload size
- Reading documents from an NDJSON file

Key concepts:
1. Calculate the overhead per document (index action line + newlines)
2. Track accumulated bytes as documents are added to the batch
3. When adding a document would exceed the limit, flush the current batch first
4. Handle any remaining documents at the end

Prerequisites:
- Sample data file must exist at: examples/data/sample_products.ndjson
- Generate it by running: python examples/generate_sample_data.py
"""

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional

from infino_sdk import InfinoError, InfinoSDK

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Default maximum payload size (3.2 MB to stay safely under 4 MB limit)
DEFAULT_MAX_PAYLOAD_BYTES = 3.2 * 1024 * 1024

# Data file path relative to this script
DATA_FILE = Path(__file__).parent / "data" / "sample_products.ndjson"


class ChunkedIngester:
    """
    Handles bulk document ingestion with automatic size-based chunking.

    This class batches documents into payloads that stay under a specified
    size limit, automatically flushing when the limit would be exceeded.
    """

    def __init__(
        self,
        sdk: InfinoSDK,
        dataset_name: str,
        max_payload_bytes: float = DEFAULT_MAX_PAYLOAD_BYTES,
    ):
        """
        Initialize the chunked ingester.

        Args:
            sdk: Initialized InfinoSDK instance
            dataset_name: Target dataset name
            max_payload_bytes: Maximum size in bytes for each bulk request
        """
        self.sdk = sdk
        self.dataset_name = dataset_name
        self.max_payload_bytes = max_payload_bytes

        # Pre-calculate the index action and overhead
        self.index_action = json.dumps({"index": {"_index": dataset_name}})
        self.overhead_per_doc = len(self.index_action.encode("utf-8")) + 2  # +2 for newlines

        # Batch state
        self._batch_lines: List[str] = []
        self._batch_bytes = 0
        self._docs_in_batch = 0

        # Cumulative statistics
        self.total_ingested = 0
        self.total_errors = 0
        self.total_batches = 0

    def _flush_batch(self) -> bool:
        """
        Send the current batch to Infino.

        Returns:
            True if batch was sent successfully, False otherwise
        """
        if not self._batch_lines:
            return True

        self.total_batches += 1
        bulk_payload = "\n".join(self._batch_lines) + "\n"
        batch_size_mb = self._batch_bytes / (1024 * 1024)
        docs_in_batch = self._docs_in_batch

        try:
            result = self.sdk.upload_json_to_dataset(self.dataset_name, bulk_payload)

            # Count errors in response
            batch_errors = 0
            if result.get("errors"):
                for item in result.get("items", []):
                    for action_result in item.values():
                        if action_result.get("status", 200) >= 400:
                            batch_errors += 1

            self.total_ingested += docs_in_batch
            self.total_errors += batch_errors

            logger.info(
                "Batch %d: %d docs, %.2f MB%s",
                self.total_batches,
                docs_in_batch,
                batch_size_mb,
                " (%d errors)" % batch_errors if batch_errors else "",
            )

            success = True

        except InfinoError as e:
            logger.error("Batch %d failed: %s", self.total_batches, e.message)
            self.total_errors += docs_in_batch
            success = False

        # Reset batch state
        self._batch_lines = []
        self._batch_bytes = 0
        self._docs_in_batch = 0

        return success

    def add_document(self, doc: Dict[str, Any]) -> None:
        """
        Add a document to the current batch, flushing if necessary.

        Args:
            doc: Document dictionary to ingest
        """
        doc_json = json.dumps(doc)
        doc_size_bytes = len(doc_json.encode("utf-8")) + self.overhead_per_doc

        # Flush if adding this doc would exceed the limit
        if self._batch_bytes + doc_size_bytes > self.max_payload_bytes and self._batch_lines:
            self._flush_batch()

        # Add document to batch
        self._batch_lines.append(self.index_action)
        self._batch_lines.append(doc_json)
        self._batch_bytes += doc_size_bytes
        self._docs_in_batch += 1

    def flush(self) -> None:
        """Flush any remaining documents in the batch."""
        self._flush_batch()

    def ingest_all(
        self,
        documents: Iterator[Dict[str, Any]],
        on_progress: Optional[Callable[[int], None]] = None,
    ) -> Dict[str, Any]:
        """
        Ingest all documents from an iterator.

        Args:
            documents: Iterator of document dictionaries
            on_progress: Optional callback called with document count periodically

        Returns:
            Summary dict with total_ingested, total_batches, total_errors
        """
        doc_count = 0
        for doc in documents:
            self.add_document(doc)
            doc_count += 1
            if on_progress and doc_count % 10000 == 0:
                on_progress(doc_count)

        self.flush()

        return {
            "total_ingested": self.total_ingested,
            "total_batches": self.total_batches,
            "total_errors": self.total_errors,
        }


def read_ndjson_file(file_path: Path) -> Iterator[Dict[str, Any]]:
    """
    Read documents from an NDJSON file (one JSON object per line).

    Args:
        file_path: Path to the NDJSON file

    Yields:
        Document dictionaries

    Raises:
        FileNotFoundError: If the file does not exist
        json.JSONDecodeError: If a line is not valid JSON
    """
    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                logger.error("Invalid JSON at line %d: %s", line_num, e)
                raise


def ingest_documents_with_chunking(
    sdk: InfinoSDK,
    documents: Iterator[Dict[str, Any]],
    dataset_name: str,
    max_payload_bytes: float = DEFAULT_MAX_PAYLOAD_BYTES,
) -> Dict[str, Any]:
    """
    Ingest documents in batches that respect the maximum payload size.

    This is a convenience function that wraps ChunkedIngester for simple use cases.

    Args:
        sdk: Initialized InfinoSDK instance
        documents: Iterator of document dictionaries to ingest
        dataset_name: Target dataset name
        max_payload_bytes: Maximum size in bytes for each bulk request

    Returns:
        Summary dict with total_ingested, total_batches, total_errors

    Example:
        sdk = InfinoSDK(access_key, secret_key, endpoint)
        documents = read_ndjson_file(Path("data.ndjson"))

        result = ingest_documents_with_chunking(
            sdk=sdk,
            documents=documents,
            dataset_name="my_dataset",
            max_payload_bytes=3.2 * 1024 * 1024,
        )
        logger.info("Ingested %d documents", result["total_ingested"])
    """
    ingester = ChunkedIngester(sdk, dataset_name, max_payload_bytes)
    return ingester.ingest_all(documents)


def main():
    # Check for required data file
    if not DATA_FILE.exists():
        logger.error("Data file not found: %s", DATA_FILE)
        logger.error("Please ensure the sample data file exists before running this example.")
        sys.exit(1)

    access_key = os.getenv("INFINO_ACCESS_KEY", "your_access_key")
    secret_key = os.getenv("INFINO_SECRET_KEY", "your_secret_key")
    endpoint = os.getenv("INFINO_ENDPOINT", "https://api.infino.ws")

    sdk = InfinoSDK(access_key, secret_key, endpoint)
    logger.info("Connected to Infino")

    dataset_name = "chunked_upload_demo"

    # Create dataset
    try:
        sdk.create_dataset(dataset_name)
        logger.info("Created dataset: %s", dataset_name)
    except InfinoError as e:
        if e.status_code() == 409:
            logger.info("Dataset %s already exists", dataset_name)
        else:
            raise

    try:
        # Get file info
        file_size_mb = DATA_FILE.stat().st_size / (1024 * 1024)
        logger.info("Reading from: %s (%.2f MB)", DATA_FILE.name, file_size_mb)

        # Count lines for progress reporting
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            total_lines = sum(1 for line in f if line.strip())
        logger.info("Total documents to ingest: %d", total_lines)

        # Create ingester and log configuration
        ingester = ChunkedIngester(sdk, dataset_name)
        logger.info("Max payload size: %.1f MB per batch", DEFAULT_MAX_PAYLOAD_BYTES / (1024 * 1024))

        # Ingest with chunking
        logger.info("Starting bulk ingestion")
        start_time = time.time()

        documents = read_ndjson_file(DATA_FILE)
        result = ingester.ingest_all(documents)

        elapsed = time.time() - start_time

        # Report results
        logger.info(
            "Ingestion complete: %d docs, %d batches, %d errors, %.2f sec (%.0f docs/sec)",
            result["total_ingested"],
            result["total_batches"],
            result["total_errors"],
            elapsed,
            result["total_ingested"] / elapsed if elapsed > 0 else 0,
        )

        # Verify upload
        time.sleep(2)  # Wait for indexing
        query = '{"query": {"match_all": {}}, "size": 0, "track_total_hits": true}'
        results = sdk.query_dataset_in_querydsl(dataset_name, query)
        total = results.get("hits", {}).get("total", {}).get("value", 0)
        logger.info("Verified %d records in dataset", total)

        # Sample query
        query = '{"query": {"term": {"category": "electronics"}}, "size": 3}'
        results = sdk.query_dataset_in_querydsl(dataset_name, query)
        hits = results.get("hits", {}).get("hits", [])
        logger.info("Sample query returned %d electronics products", len(hits))
        for hit in hits:
            source = hit["_source"]
            logger.debug("  %s ($%.2f)", source["name"], source["price"])

    finally:
        # Cleanup
        logger.info("Cleaning up - deleting dataset")
        sdk.delete_dataset(dataset_name)
        logger.info("Deleted dataset: %s", dataset_name)


if __name__ == "__main__":
    main()
