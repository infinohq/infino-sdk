"""Tests for file upload functionality."""

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from infino_sdk import InfinoError, InfinoSDK


@pytest.fixture
def sdk():
    """Create SDK instance for testing."""
    return InfinoSDK(
        access_key="test_key",
        secret_key="test_secret",
        endpoint="http://localhost:8000",
    )


@pytest.fixture
def temp_json_file():
    """Create temporary JSON file for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump([{"id": 1, "name": "test"}], f)
        temp_path = f.name
    yield temp_path
    os.unlink(temp_path)


@pytest.fixture
def temp_csv_file():
    """Create temporary CSV file for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write("id,name\n1,test\n2,test2\n")
        temp_path = f.name
    yield temp_path
    os.unlink(temp_path)


@pytest.fixture
def temp_jsonl_file():
    """Create temporary JSONL file for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write('{"id": 1, "name": "test"}\n')
        f.write('{"id": 2, "name": "test2"}\n')
        temp_path = f.name
    yield temp_path
    os.unlink(temp_path)


class TestUploadFile:
    """Tests for upload_file method."""

    def test_upload_file_sync_success(self, sdk, temp_json_file):
        """Test sync file upload success."""
        mock_response = {
            "connector_id": "file",
            "run_id": "test-uuid",
            "status": "completed",
            "message": "File processed successfully",
            "stats": {
                "documents_processed": 1,
                "documents_failed": 0,
            },
            "errors": [],
        }

        with patch.object(sdk, "request_multipart", return_value=mock_response):
            result = sdk.upload_file("test_dataset", temp_json_file)

            assert result["status"] == "completed"
            assert result["stats"]["documents_processed"] == 1

    def test_upload_file_async_success(self, sdk, temp_json_file):
        """Test async file upload returns run_id."""
        mock_response = {
            "connector_id": "file",
            "run_id": "test-uuid-123",
            "status": "submitted",
            "message": "File submitted for processing",
            "stats": None,
            "errors": [],
        }

        with patch.object(sdk, "request_multipart", return_value=mock_response):
            result = sdk.upload_file("test_dataset", temp_json_file, async_mode=True)

            assert result["status"] == "submitted"
            assert result["run_id"] == "test-uuid-123"

    def test_upload_file_not_found(self, sdk):
        """Test upload with non-existent file raises error."""
        with pytest.raises(InfinoError) as exc_info:
            sdk.upload_file("test_dataset", "/nonexistent/file.json")

        assert "File not found" in str(exc_info.value.message)

    def test_upload_file_csv(self, sdk, temp_csv_file):
        """Test CSV file upload."""
        mock_response = {"status": "completed", "run_id": "test"}

        with patch.object(sdk, "request_multipart", return_value=mock_response) as mock:
            sdk.upload_file("test_dataset", temp_csv_file, format="csv")

            # Verify format was passed correctly
            call_args = mock.call_args
            assert call_args[0][3]["format"] == "csv"

    def test_upload_file_jsonl(self, sdk, temp_jsonl_file):
        """Test JSONL file upload."""
        mock_response = {"status": "completed", "run_id": "test"}

        with patch.object(sdk, "request_multipart", return_value=mock_response) as mock:
            sdk.upload_file("test_dataset", temp_jsonl_file, format="jsonl")

            call_args = mock.call_args
            assert call_args[0][3]["format"] == "jsonl"

    def test_upload_file_with_batch_size(self, sdk, temp_json_file):
        """Test upload with custom batch size."""
        mock_response = {"status": "completed", "run_id": "test"}

        with patch.object(sdk, "request_multipart", return_value=mock_response) as mock:
            sdk.upload_file("test_dataset", temp_json_file, batch_size=1000)

            call_args = mock.call_args
            assert call_args[0][3]["batch_size"] == "1000"

    def test_upload_file_auto_format(self, sdk, temp_json_file):
        """Test upload with auto format detection."""
        mock_response = {"status": "completed", "run_id": "test"}

        with patch.object(sdk, "request_multipart", return_value=mock_response) as mock:
            sdk.upload_file("test_dataset", temp_json_file)  # format defaults to "auto"

            call_args = mock.call_args
            assert call_args[0][3]["format"] == "auto"

    def test_upload_file_url_and_params(self, sdk, temp_json_file):
        """Test that upload_file uses correct URL and params."""
        mock_response = {"status": "completed", "run_id": "test"}

        with patch.object(sdk, "request_multipart", return_value=mock_response) as mock:
            sdk.upload_file("test_dataset", temp_json_file, async_mode=False)

            call_args = mock.call_args
            # Check URL
            assert call_args[0][1] == "http://localhost:8000/import/file"
            # Check async param
            assert call_args[0][4] == {"async": "false"}

    def test_upload_file_async_params(self, sdk, temp_json_file):
        """Test that async_mode=True sets correct query param."""
        mock_response = {"status": "submitted", "run_id": "test"}

        with patch.object(sdk, "request_multipart", return_value=mock_response) as mock:
            sdk.upload_file("test_dataset", temp_json_file, async_mode=True)

            call_args = mock.call_args
            assert call_args[0][4] == {"async": "true"}


class TestGetConnectorJobStatus:
    """Tests for get_connector_job_status method."""

    def test_get_job_status_completed(self, sdk):
        """Test getting completed job status."""
        mock_response = {
            "run_id": "test-uuid",
            "status": "completed",
            "stats": {"documents_processed": 100},
        }

        with patch.object(sdk, "request", return_value=mock_response):
            result = sdk.get_connector_job_status("test-uuid")

            assert result["status"] == "completed"
            assert result["stats"]["documents_processed"] == 100

    def test_get_job_status_running(self, sdk):
        """Test getting status of running job."""
        mock_response = {"run_id": "test-uuid", "status": "running", "stats": None}

        with patch.object(sdk, "request", return_value=mock_response):
            result = sdk.get_connector_job_status("test-uuid")

            assert result["status"] == "running"

    def test_get_job_status_failed(self, sdk):
        """Test getting status of failed job."""
        mock_response = {
            "run_id": "test-uuid",
            "status": "failed",
            "errors": ["Parse error on line 5"],
        }

        with patch.object(sdk, "request", return_value=mock_response):
            result = sdk.get_connector_job_status("test-uuid")

            assert result["status"] == "failed"
            assert "Parse error" in result["errors"][0]

    def test_get_job_status_url(self, sdk):
        """Test that get_connector_job_status uses correct URL."""
        mock_response = {"run_id": "my-job-id", "status": "completed"}

        with patch.object(sdk, "request", return_value=mock_response) as mock:
            sdk.get_connector_job_status("my-job-id")

            call_args = mock.call_args
            assert call_args[0][0] == "GET"
            assert call_args[0][1] == "http://localhost:8000/_connectors/jobs/my-job-id"


class TestRequestMultipart:
    """Tests for multipart request handling."""

    def test_multipart_uses_unsigned_payload(self, sdk):
        """Test that multipart requests use UNSIGNED-PAYLOAD for signing."""
        with patch.object(sdk, "sign_request_headers") as mock_sign:
            with patch.object(sdk, "execute_multipart_request", return_value={}):
                mock_sign.return_value = {}

                sdk.request_multipart(
                    "POST",
                    "http://localhost:8000/import/file",
                    files={"file": ("test.json", b"content", "application/json")},
                    data={"index_name": "test"},
                )

                # Verify UNSIGNED-PAYLOAD was passed to sign_request_headers
                call_args = mock_sign.call_args
                assert call_args[0][4] == "UNSIGNED-PAYLOAD"

    def test_multipart_does_not_set_content_type(self, sdk):
        """Test that multipart request does not manually set Content-Type header."""
        with patch.object(sdk, "sign_request_headers") as mock_sign:
            with patch.object(sdk, "execute_multipart_request", return_value={}):
                mock_sign.return_value = {
                    "X-Amz-Date": "test",
                    "X-Amz-Content-Sha256": "test",
                }

                sdk.request_multipart(
                    "POST",
                    "http://localhost:8000/import/file",
                    files={"file": ("test.json", b"content", "application/json")},
                    data={"index_name": "test"},
                )

                # Verify Content-Type is NOT in the headers we create
                # (requests library will add it with boundary)
                call_args = mock_sign.call_args
                headers = call_args[0][2]
                assert "Content-Type" not in headers

    def test_execute_multipart_request_success(self, sdk):
        """Test successful multipart request execution."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"status": "completed"}'

        with patch.object(sdk.session, "request", return_value=mock_response):
            result = sdk.execute_multipart_request(
                "POST",
                "http://localhost:8000/import/file",
                headers={"Authorization": "test"},
                files={"file": ("test.json", b"content", "application/json")},
                data={"index_name": "test"},
                params={"async": "false"},
            )

            assert result["status"] == "completed"

    def test_execute_multipart_request_client_error(self, sdk):
        """Test multipart request with client error."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad request"

        with patch.object(sdk.session, "request", return_value=mock_response):
            with pytest.raises(InfinoError) as exc_info:
                sdk.execute_multipart_request(
                    "POST",
                    "http://localhost:8000/import/file",
                    headers={},
                    files={},
                    data={},
                    params=None,
                )

            assert exc_info.value._status_code == 400
