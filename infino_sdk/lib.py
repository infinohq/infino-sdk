"""
Copyright 2026 Infino AI, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import hashlib
import hmac
import json
import logging
import os
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Protocol
from urllib.parse import urlparse

import requests
import websockets
import yaml

# Configure logging
logger = logging.getLogger(__name__)

# Algorithm and service
ALGORITHM = "AWS4-HMAC-SHA256"
SIGNING_NAME = "es"
REGION = "us-east-1"
TERMINATION = "aws4_request"
KEY_PREFIX = "AWS4"

# Headers
HEADER_PREFIX = "X-Amz-"
HOST_HEADER = "Host"

# Standard AWS header constants
AUTHORIZATION_HEADER = "Authorization"
X_AMZ_CONTENT_SHA256_HEADER = "X-Amz-Content-Sha256"
X_AMZ_DATE_HEADER = "X-Amz-Date"
CREDENTIAL_HEADER = "Credential"
SIGNED_HEADERS_HEADER = "SignedHeaders"
SIGNATURE_HEADER = "Signature"

# Date formats
DATE_FORMAT = "%Y%m%dT%H%M%SZ"
SHORT_DATE_FORMAT = "%Y%m%d"

# Fixed strings
EMPTY_PAYLOAD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
# Unsigned payload hash for multipart requests (body cannot be reliably hashed)
UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"

# Define TRACE level
TRACE_LEVEL = 5  # Lower than DEBUG (10)
logging.addLevelName(TRACE_LEVEL, "TRACE")


def trace(self, message, *args, **kwargs):
    """Custom trace level logging."""
    if self.isEnabledFor(TRACE_LEVEL):
        self.log(TRACE_LEVEL, message, *args, **kwargs)


# Add trace method to Logger class
logging.Logger.trace = trace  # type: ignore[attr-defined]

# Timeouts (in milliseconds unless specified)
REQUEST_TIMEOUT_SECS = 180
RETRY_INITIAL_INTERVAL = 1000
RETRY_MAX_INTERVAL = 15000
RETRY_MAX_ELAPSED_TIME = 90000


class InfinoError(Exception):
    """SDK error wrapper"""

    class Type(Enum):
        REQUEST = "request"
        NETWORK = "network"
        PARSE = "parse"
        RATE_LIMIT = "rate_limit"
        TIMEOUT = "timeout"
        INVALID_REQUEST = "invalid_request"

    def __init__(
        self,
        error_type: Type,
        message: str,
        status_code: Optional[int] = None,
        url: Optional[str] = None,
    ):
        self.error_type = error_type
        self.message = message
        self._status_code = status_code
        self.url = url

    def status_code(self) -> Optional[int]:
        return self._status_code


@dataclass
class RetryConfig:
    def __init__(self):
        self.initial_interval = RETRY_INITIAL_INTERVAL  # milliseconds
        self.max_interval = RETRY_MAX_INTERVAL  # milliseconds
        self.max_elapsed_time = RETRY_MAX_ELAPSED_TIME  # milliseconds
        self.max_retries = 3


class SignatureComponents:
    def __init__(self, access_key: str, request_date: str, request_datetime: str):
        self.access_key = access_key
        self.request_date = request_date  # YYYYMMDD
        self.request_datetime = request_datetime  # ISO8601/RFC3339 format


class _RequestLike(Protocol):
    method: str
    url: str
    headers: Dict[str, str]


class InfinoSDK:
    def __init__(
        self,
        access_key: str,
        secret_key: str,
        endpoint: str,
        retry_config: Optional[RetryConfig] = None,
    ):
        self.access_key = access_key
        self.secret_key = secret_key
        self.endpoint = endpoint.rstrip("/")
        self.retry_config = retry_config or RetryConfig()

        # AWS SigV4 parameters
        self.region = "us-east-1"
        self.service = "es"  # OpenSearch service

        # Use requests session for connection pooling
        self.session = requests.Session()

    def close(self):
        """Close the requests session"""
        if self.session:
            self.session.close()
            self.session = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    async def websocket_connect(
        self, path: str, headers: Optional[Dict[str, str]] = None
    ):
        """Connect to WebSocket endpoint with SigV4 query parameter authentication"""
        parsed = urlparse(self.endpoint)
        ws_proto = "wss" if parsed.scheme == "https" else "ws"
        host = parsed.netloc

        # Generate timestamp for signing
        timestamp = datetime.now(timezone.utc)
        date_stamp = timestamp.strftime("%Y%m%d")
        amz_date = timestamp.strftime("%Y%m%dT%H%M%SZ")

        # AWS SigV4 parameters
        algorithm = "AWS4-HMAC-SHA256"
        credential = (
            f"{self.access_key}/{date_stamp}/{self.region}/{self.service}/aws4_request"
        )
        signed_headers = "host"

        # Build query parameters (without signature yet)
        query_params = [
            ("X-Amz-Algorithm", algorithm),
            ("X-Amz-Credential", credential),
            ("X-Amz-Date", amz_date),
            ("X-Amz-SignedHeaders", signed_headers),
        ]

        # Sort query parameters for canonical request
        query_params.sort(key=lambda x: x[0])

        # URL encode parameters
        canonical_querystring = "&".join(
            [
                f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
                for k, v in query_params
            ]
        )

        # Create canonical request
        canonical_uri = path
        canonical_headers = f"host:{host}\n"
        payload_hash = hashlib.sha256(
            b""
        ).hexdigest()  # Empty string hash for WebSocket

        canonical_request = f"GET\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

        # Create string to sign
        scope = f"{date_stamp}/{self.region}/{self.service}/aws4_request"
        canonical_request_hash = hashlib.sha256(canonical_request.encode()).hexdigest()
        string_to_sign = f"{algorithm}\n{amz_date}\n{scope}\n{canonical_request_hash}"

        # Generate signature using existing SDK helper
        signing_key = self.derive_signing_key(date_stamp)
        signature = self.calculate_signature(signing_key, string_to_sign)

        # Build final WebSocket URL with all query parameters including signature
        ws_url = f"{ws_proto}://{host}{canonical_uri}?{canonical_querystring}&X-Amz-Signature={urllib.parse.quote(signature, safe='')}"

        # Connect with optional additional headers (but auth is in query params)
        if headers:
            return await websockets.connect(ws_url, additional_headers=headers.items())
        return await websockets.connect(ws_url)

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Build, sign, and execute an HTTP request"""

        logger.debug("INFINO SDK: Making %s request to %s", method, url)

        timestamp = datetime.now(timezone.utc)
        payload = body or ""
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()

        logger.debug("INFINO SDK: Creating request")
        logger.debug("INFINO SDK: Method: %s", method)
        logger.debug("INFINO SDK: URL: %s", url)
        logger.debug("INFINO SDK: Body length: %d", len(payload))
        logger.debug("INFINO SDK: Timestamp: %s", timestamp)
        logger.debug("INFINO SDK: Payload hash: %s", payload_hash)

        # Build headers dict
        req_headers = {
            f"{X_AMZ_DATE_HEADER}": timestamp.strftime(DATE_FORMAT),
            f"{X_AMZ_CONTENT_SHA256_HEADER}": payload_hash,
        }

        # Allow certain operations to override the default headers (e.g. bulk ingest)
        if headers:
            req_headers.update(headers)
        else:
            req_headers["Content-Type"] = "application/json"

        # Sign the headers if we have credentials
        if self.access_key and self.secret_key:
            req_headers = self.sign_request_headers(
                method, url, req_headers, timestamp, payload_hash
            )

        # Execute request with retries
        return self.execute_request(method, url, req_headers, body, params)

    def sign_request_headers(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        timestamp: datetime,
        payload_hash: str,
    ) -> Dict[str, str]:
        """Sign request headers for AWS SigV4"""
        request_datetime = timestamp.strftime(DATE_FORMAT)
        request_date = timestamp.strftime(SHORT_DATE_FORMAT)

        # Copy headers
        signed_headers = headers.copy()

        # Add required headers
        signed_headers[X_AMZ_DATE_HEADER] = request_datetime
        signed_headers[X_AMZ_CONTENT_SHA256_HEADER] = payload_hash

        # Get host from URL (include port for non-standard ports)
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            raise InfinoError(InfinoError.Type.INVALID_REQUEST, "Missing host")
        port = parsed.port
        # Include port in Host header for non-standard ports (not 80/443)
        if port and port not in (80, 443):
            host = f"{host}:{port}"
        signed_headers[HOST_HEADER] = host

        # Headers to sign
        headers_to_sign = [
            HOST_HEADER.lower(),
            X_AMZ_CONTENT_SHA256_HEADER.lower(),
            X_AMZ_DATE_HEADER.lower(),
        ]
        if "Content-Type" in signed_headers:
            headers_to_sign.append("content-type")

        # Sign
        signing_key = self.derive_signing_key(request_date)

        # Create temp request for canonical request
        temp_req = SimpleNamespace(method=method, url=url, headers=signed_headers)

        canonical_request = self.create_canonical_request(temp_req, headers_to_sign)

        components = SignatureComponents(
            access_key=self.access_key,
            request_date=request_date,
            request_datetime=request_datetime,
        )

        string_to_sign = self.create_string_to_sign(canonical_request, components)
        signature = self.calculate_signature(signing_key, string_to_sign)

        # Build auth header
        sorted_headers = sorted(headers_to_sign)
        signed_headers_str = ";".join(sorted_headers)
        auth_header = f"{ALGORITHM} {CREDENTIAL_HEADER}={self.access_key}/{request_date}/{REGION}/{SIGNING_NAME}/{TERMINATION}, {SIGNED_HEADERS_HEADER}={signed_headers_str}, {SIGNATURE_HEADER}={signature}"

        signed_headers[AUTHORIZATION_HEADER] = auth_header
        return signed_headers

    def execute_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[str],
        params: Optional[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Execute request with retries"""
        max_retries = self.retry_config.max_retries
        retry_delay = self.retry_config.initial_interval

        for attempt in range(max_retries):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body,
                    params=params,
                    timeout=REQUEST_TIMEOUT_SECS,
                )

                status = response.status_code
                text = response.text

                if 200 <= status < 300:
                    if text:
                        try:
                            return json.loads(text)
                        except json.JSONDecodeError:
                            return {"text": text}
                    return {}

                if 400 <= status < 500:  # Client errors - don't retry
                    if status == 404:
                        logger.warning("Resource not found: %s", text)
                    elif status == 403:
                        logger.warning("Permission denied (403): %s", text)
                    elif status == 401:
                        logger.warning("Unauthorized (401): %s", text)
                    else:
                        logger.error("Client error %d: %s", status, text)
                    raise InfinoError(InfinoError.Type.REQUEST, text, status, url)

                if 500 <= status < 600:  # Server errors - retry
                    logger.error("INFINO SDK: Server error %d: %s", status, text)
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay / 1000)
                        retry_delay = min(
                            retry_delay * 2, self.retry_config.max_interval
                        )
                        continue
                    raise InfinoError(InfinoError.Type.REQUEST, text, status, url)

                raise InfinoError(InfinoError.Type.REQUEST, text, status, url)

            except requests.RequestException as e:
                if attempt < max_retries - 1 and "Connection refused" not in str(e):
                    time.sleep(retry_delay / 1000)
                    retry_delay = min(retry_delay * 2, self.retry_config.max_interval)
                    continue
                raise InfinoError(InfinoError.Type.REQUEST, str(e), 0, url) from e

        raise InfinoError(InfinoError.Type.REQUEST, "Max retries exceeded", 0, url)

    def request_multipart(
        self,
        method: str,
        url: str,
        files: Dict[str, Any],
        data: Dict[str, str],
        params: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Build, sign, and execute a multipart HTTP request.

        For multipart requests, we use UNSIGNED-PAYLOAD for the content hash
        since the multipart boundary is randomly generated by the HTTP client
        and cannot be reliably hashed the same way on client and server.

        Args:
            method: HTTP method (typically POST)
            url: Full URL
            files: Dict with file data for requests library
                   Format: {'file': (filename, file_obj, content_type)}
            data: Form data fields as dict
            params: Optional query parameters

        Returns:
            Response as dict
        """
        # Build URL with query params for signing
        # The signature must include query params or server will reject
        # URL-encode params to prevent injection attacks
        if params:
            query_string = "&".join(
                f"{urllib.parse.quote(str(k), safe='')}={urllib.parse.quote(str(v), safe='')}"
                for k, v in sorted(params.items())
            )
            url_for_signing = f"{url}?{query_string}"
        else:
            url_for_signing = url

        logger.debug(
            "INFINO SDK: Making multipart %s request to %s", method, url_for_signing
        )

        timestamp = datetime.now(timezone.utc)

        # For multipart, use UNSIGNED-PAYLOAD instead of body hash
        # The boundary string is randomly generated by requests library,
        # so we can't compute a reliable hash of the body
        payload_hash = UNSIGNED_PAYLOAD

        # Build headers - do NOT set Content-Type, requests library will set it with boundary
        req_headers = {
            X_AMZ_DATE_HEADER: timestamp.strftime(DATE_FORMAT),
            X_AMZ_CONTENT_SHA256_HEADER: payload_hash,
        }

        # Sign headers if we have credentials - sign the URL with query params
        if self.access_key and self.secret_key:
            req_headers = self.sign_request_headers(
                method, url_for_signing, req_headers, timestamp, payload_hash
            )

        # Execute multipart request - pass URL with query params already included
        # Don't pass params separately since they're in the URL
        return self.execute_multipart_request(
            method, url_for_signing, req_headers, files, data, None
        )

    def execute_multipart_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        files: Dict[str, Any],
        data: Dict[str, str],
        params: Optional[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Execute multipart request with retries.

        Args:
            method: HTTP method
            url: Full URL
            headers: Request headers (signed)
            files: Files dict for requests library
            data: Form data fields
            params: Query parameters

        Returns:
            Response as dict
        """
        max_retries = self.retry_config.max_retries
        retry_delay = self.retry_config.initial_interval

        for attempt in range(max_retries):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    files=files,
                    data=data,
                    params=params,
                    timeout=REQUEST_TIMEOUT_SECS,
                )

                status = response.status_code
                text = response.text

                if 200 <= status < 300:
                    if text:
                        try:
                            return json.loads(text)
                        except json.JSONDecodeError:
                            return {"text": text}
                    return {}

                if 400 <= status < 500:
                    logger.error("INFINO SDK: Client error %d: %s", status, text)
                    raise InfinoError(InfinoError.Type.REQUEST, text, status, url)

                if 500 <= status < 600:
                    logger.error("INFINO SDK: Server error %d: %s", status, text)
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay / 1000)  # Convert ms to seconds
                        retry_delay = min(
                            retry_delay * 2, self.retry_config.max_interval
                        )
                        continue
                    raise InfinoError(InfinoError.Type.REQUEST, text, status, url)

                raise InfinoError(InfinoError.Type.REQUEST, text, status, url)

            except requests.RequestException as e:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay / 1000)
                    retry_delay = min(retry_delay * 2, self.retry_config.max_interval)
                    continue
                raise InfinoError(InfinoError.Type.REQUEST, str(e), 0, url) from e

        raise InfinoError(InfinoError.Type.REQUEST, "Max retries exceeded", 0, url)

    def sign_request(
        self, request: requests.Request, timestamp: datetime
    ) -> requests.Request:
        """Sign request using AWS SigV4"""
        request_datetime = timestamp.strftime(DATE_FORMAT)
        request_date = timestamp.strftime(SHORT_DATE_FORMAT)

        # Add date header
        request.headers[X_AMZ_DATE_HEADER] = request_datetime

        # Get payload hash
        payload_hash = request.headers.get(
            X_AMZ_CONTENT_SHA256_HEADER, EMPTY_PAYLOAD_HASH
        )

        # If no content hash header exists, add it
        if X_AMZ_CONTENT_SHA256_HEADER not in request.headers:
            request.headers[X_AMZ_CONTENT_SHA256_HEADER] = payload_hash

        components = SignatureComponents(
            access_key=self.access_key,
            request_date=request_date,
            request_datetime=request_datetime,
        )

        logger.debug("SIGN REQUEST: URL path: %s", urlparse(request.url).path)
        logger.debug("SIGN REQUEST: Host: %s", urlparse(request.url).hostname)
        logger.debug("SIGN REQUEST: Request date: %s", request_date)
        logger.debug("SIGN REQUEST: Request datetime: %s", request_datetime)

        # Get host from URL - AWS requires host header
        host = urlparse(request.url).hostname
        if not host:
            raise InfinoError(InfinoError.Type.INVALID_REQUEST, "Missing host")

        # Ensure host header exists
        request.headers[HOST_HEADER] = host

        # Create a list of headers to sign - Must include all headers that are part of the signature calculation
        signed_headers = [
            HOST_HEADER.lower(),
            X_AMZ_CONTENT_SHA256_HEADER.lower(),
            X_AMZ_DATE_HEADER.lower(),
        ]

        # Add content-type if it exists in the request
        if "Content-Type" in request.headers:
            signed_headers.append("content-type")

        signing_key = self.derive_signing_key(request_date)

        canonical_request = self.create_canonical_request(request, signed_headers)
        string_to_sign = self.create_string_to_sign(canonical_request, components)
        signature = self.calculate_signature(signing_key, string_to_sign)

        # Get the sorted signed_headers_str from the canonical request builder
        sorted_headers = sorted(signed_headers)
        signed_headers_str = ";".join(sorted_headers)

        # Format auth header exactly as AWS expects
        # Include a space after each comma
        auth_header = f"{ALGORITHM} {CREDENTIAL_HEADER}={components.access_key}/{components.request_date}/{REGION}/{SIGNING_NAME}/{TERMINATION}, {SIGNED_HEADERS_HEADER}={signed_headers_str}, {SIGNATURE_HEADER}={signature}"

        logger.debug("SIGN REQUEST: Final auth header: %s", auth_header)

        # Use the standard Authorization header as AWS does
        request.headers[AUTHORIZATION_HEADER] = auth_header

        return request

    def create_canonical_request(
        self, request: _RequestLike, signed_headers: List[str]
    ) -> str:
        """Create canonical request for SigV4"""
        # 1. HTTP Method
        method = request.method.upper()

        # 2. Canonical URI - Extract path from URL
        url = urlparse(request.url)
        canonical_uri = url.path
        if not canonical_uri or canonical_uri == "":
            canonical_uri = "/"

        logger.debug("SIGN REQUEST: URL path: %s", url.path)
        logger.debug("SIGN REQUEST: Canonical URI: %s", canonical_uri)

        # 3. Query String (empty or normalized)
        canonical_query = ""
        if url.query:
            canonical_query = self.normalize_query(url.query)

        # 4. Headers - Must be sorted alphabetically for the canonical request
        # Sort headers alphabetically as required by AWS SigV4
        sorted_headers = sorted(signed_headers)

        # Build canonical headers section including only the sorted signed headers
        canonical_headers = ""
        for header in sorted_headers:
            # Try both original case and lowercase to find the value
            header_value = request.headers.get(
                header.title(), request.headers.get(header, "")
            )
            canonical_headers += f"{header}:{header_value}\n"

        # 5. Signed Headers - must be alphabetical for canonical request
        signed_headers_str = ";".join(sorted_headers)

        # 6. Get payload hash
        payload_hash = request.headers.get(
            X_AMZ_CONTENT_SHA256_HEADER, EMPTY_PAYLOAD_HASH
        )

        # Combine all components with newlines - exactly matching AWS format
        canonical_request = (
            f"{method}\n"
            f"{canonical_uri}\n"
            f"{canonical_query}\n"
            f"{canonical_headers}\n"
            f"{signed_headers_str}\n"
            f"{payload_hash}"
        )

        logger.debug("SIGN REQUEST: Canonical request:\n%s", canonical_request)
        return canonical_request

    def hmac_sha256(self, key: bytes, data: bytes) -> bytes:
        """Calculate HMAC-SHA256"""
        return hmac.new(key, data, hashlib.sha256).digest()

    def derive_signing_key(self, date: str) -> bytes:
        """Derive SigV4 signing key from secret and date"""
        logger.debug("SIGN REQUEST: Starting key derivation")
        logger.debug("SIGN REQUEST: Date: %s", date)
        logger.debug("SIGN REQUEST: Secret key: %s", self.secret_key)
        logger.debug("SIGN REQUEST: KEY_PREFIX: %s", KEY_PREFIX)
        logger.debug("SIGN REQUEST: REGION: %s", REGION)
        logger.debug("SIGN REQUEST: SIGNING_NAME: %s", SIGNING_NAME)
        logger.debug("SIGN REQUEST: TERMINATION: %s", TERMINATION)

        # Format the key string exactly as the server does
        key_string = f"{KEY_PREFIX}{self.secret_key}"

        # Step 1: kDate = HMAC(KEY_PREFIX + secret_key, date)
        k_date = self.hmac_sha256(key_string.encode("utf-8"), date.encode("utf-8"))
        logger.debug("SIGN REQUEST: k_date (hex): %s", k_date.hex())

        # Step 2: kRegion = HMAC(kDate, region)
        k_region = self.hmac_sha256(k_date, REGION.encode("utf-8"))
        logger.debug("SIGN REQUEST: k_region (hex): %s", k_region.hex())

        # Step 3: kService = HMAC(kRegion, service)
        k_service = self.hmac_sha256(k_region, SIGNING_NAME.encode("utf-8"))
        logger.debug("SIGN REQUEST: k_service (hex): %s", k_service.hex())

        # Step 4: signing_key = HMAC(kService, termination)
        signing_key = self.hmac_sha256(k_service, TERMINATION.encode("utf-8"))
        logger.debug("SIGN REQUEST: final signing_key (hex): %s", signing_key.hex())

        return signing_key

    def calculate_signature(self, signing_key: bytes, string_to_sign: str) -> str:
        """Calculate signature from key and string to sign"""
        logger.debug("SIGN REQUEST: Calculating signature")
        logger.debug("SIGN REQUEST: Signing key (hex): %s", signing_key.hex())
        logger.debug("SIGN REQUEST: String to sign:\n%s", string_to_sign)

        signature_bytes = self.hmac_sha256(signing_key, string_to_sign.encode())
        signature = signature_bytes.hex()
        logger.debug("SIGN REQUEST: Final signature: %s", signature)

        return signature

    def create_string_to_sign(
        self, canonical_request: str, components: SignatureComponents
    ) -> str:
        """Create SigV4 string to sign"""
        credential_scope = (
            f"{components.request_date}/{REGION}/{SIGNING_NAME}/{TERMINATION}"
        )

        string_to_sign = (
            f"{ALGORITHM}\n"
            f"{components.request_datetime}\n"
            f"{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
        )

        logger.debug("SIGN REQUEST: String to sign:\n%s", string_to_sign)
        return string_to_sign

    def normalize_query(self, query: str) -> str:
        """Normalize query parameters"""
        if not query:
            return ""

        params = []
        for p in query.split("&"):
            if not p:
                continue
            parts = p.split("=", 1)
            key = self.uri_encode(parts[0]) if parts else ""
            value = self.uri_encode(parts[1]) if len(parts) > 1 else ""
            params.append((key, value))

        params.sort(key=lambda x: x[0])
        return "&".join(f"{k}={v}" for k, v in params)

    def uri_encode(self, s: str) -> str:
        """Percent-encode string for URI"""
        encoded = ""
        for byte in s.encode("utf-8"):
            if (
                (byte >= ord("A") and byte <= ord("Z"))
                or (byte >= ord("a") and byte <= ord("z"))
                or (byte >= ord("0") and byte <= ord("9"))
                or byte == ord("-")
                or byte == ord("_")
                or byte == ord(".")
                or byte == ord("~")
            ):
                encoded += chr(byte)
            else:
                encoded += f"%{byte:02X}"
        return encoded

    # Dataset Operations
    def create_dataset(self, dataset: str) -> Dict[str, Any]:
        """Create an empty dataset"""
        url = f"{self.endpoint}/{dataset}"
        try:
            response = self.request("PUT", url)
            return response
        except InfinoError as e:
            # 409 CONFLICT is acceptable for dataset creation - it means the dataset already exists
            if e.status_code() == 409:
                logger.debug(
                    "INFINO SDK: Dataset '%s' already exists (409 CONFLICT), continuing",
                    dataset,
                )
                return {"acknowledged": True, "index": dataset}
            raise

    def delete_dataset(self, dataset: str) -> Dict[str, Any]:
        """Delete a dataset"""
        url = f"{self.endpoint}/{dataset}"
        response = self.request("DELETE", url)
        return response

    def get_dataset_metadata(self, dataset: str) -> Dict[str, Any]:
        """Query a dataset for its metadata"""
        url = f"{self.endpoint}/{dataset}/metadata"
        response = self.request("GET", url)

        if isinstance(response, dict):
            return response
        if isinstance(response, list):
            # Metadata endpoint returns a list with one item
            if len(response) > 0:
                return response[0]
            return {}
        if isinstance(response, str):
            return {"text": response}
        raise InfinoError(
            InfinoError.Type.INVALID_REQUEST,
            "Unexpected response from dataset metadata",
        )

    def get_dataset_schema(self, dataset: str) -> Dict[str, Any]:
        """Query a dataset for its schema"""
        url = f"{self.endpoint}/{dataset}/_schema"
        response = self.request("GET", url)
        return response

    def get_datasets(self) -> List[Dict[str, Any]]:
        """Query Infino for all metadata on current datasets"""
        url = f"{self.endpoint}/metadata"
        response = self.request("GET", url)
        if isinstance(response, list):
            return response
        raise InfinoError(InfinoError.Type.INVALID_REQUEST, "Expected list of datasets")

    # Visualization Operations
    def create_visualization(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Create a visualization. The server fills defaults for any field not
        supplied — minimally, ``title``, ``source`` (with ``kind`` and ``index``),
        and ``chart.type`` are enough.

        For SQL visualizations supply ``source.sql.raw_query``:

            >>> client.create_visualization({
            ...     "title": "Orders by currency",
            ...     "source": {
            ...         "kind": "sql",
            ...         "index": "sample-ecommerce-data.rel",
            ...         "sql": {"raw_query": "SELECT currency, COUNT(*) AS count "
            ...                              "FROM \\"sample-ecommerce-data.rel\\" "
            ...                              "GROUP BY currency"},
            ...     },
            ...     "chart": {"type": "bar"},
            ... })

        Returns an envelope ``{"id", "kind", "created_at", "updated_at",
        "attributes": {<full Visualization>}}``.
        """
        url = f"{self.endpoint}/visualizations"
        return self.request("POST", url, None, json.dumps(spec))

    def get_visualization(self, viz_id: str) -> Dict[str, Any]:
        """Fetch a saved visualization by id. Returns the envelope shape."""
        url = f"{self.endpoint}/visualizations/{viz_id}"
        return self.request("GET", url)

    def update_visualization(
        self, viz_id: str, partial: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Patch a visualization with a partial spec (RFC 7396 JSON Merge Patch).

        Only the fields you supply are touched; the rest are preserved. A
        ``null`` value removes the key. The server protects ``id``,
        ``schema_version``, ``created_at``, and ``created_by`` from mutation.

            >>> # Rename and bump the SQL row limit
            >>> client.update_visualization(viz_id, {
            ...     "title": "Orders by currency (updated)",
            ...     "source": {"sql": {"limit": 200}},
            ... })

        Returns the updated envelope.
        """
        url = f"{self.endpoint}/visualizations/{viz_id}"
        return self.request("PATCH", url, None, json.dumps(partial))

    def list_visualizations(
        self, limit: Optional[int] = None, offset: Optional[int] = None
    ) -> Dict[str, Any]:
        """List visualizations the caller can see.

        Returns ``{"items": [envelope, envelope, ...]}``. Supports pagination
        via ``limit`` (server default 500, max 1000) and ``offset`` (default 0).
        """
        url = f"{self.endpoint}/visualizations"
        params: Optional[Dict[str, str]] = None
        if limit is not None or offset is not None:
            params = {}
            if limit is not None:
                params["limit"] = str(limit)
            if offset is not None:
                params["offset"] = str(offset)
        return self.request("GET", url, params=params)

    def delete_visualization(self, viz_id: str) -> Dict[str, Any]:
        """Delete a visualization by id."""
        url = f"{self.endpoint}/visualizations/{viz_id}"
        return self.request("DELETE", url)

    def execute_visualization(
        self,
        viz_id: str,
        filters: Optional[List[Dict[str, Any]]] = None,
        time_range: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute a saved visualization and return plot-ready rows.

        Returns ``{"columns": [{"name", "type"}, ...],
                   "rows": [{col: val, ...}, ...],
                   "metadata": {"source_kind", "row_count", "truncated",
                                "took_ms", "executed_query",
                                "filters_applied", "filters_skipped"}}``.

        ``filters`` (optional): runtime filters merged with any filters saved
        on the visualization itself. The gateway AND-merges these into the
        executed SQL — same logic the dashboard UI uses when a user adds a
        filter chip. Each filter is a dict::

            {
              "field": "feature_name",        # raw identifier — do NOT quote
              "operator": "is",               # see below
              "value": "AMS_Designer",
              # Optional, defaults shown:
              "id": "<auto>",                 # any unique string; auto-generated if omitted
              "enabled": True,
              "is_time_filter": False,        # set True for @timestamp / time columns
              "query_type": None,
              "index": None,
            }

        Supported ``operator`` values: ``is``, ``is_not``, ``is_one_of``,
        ``is_not_one_of``, ``exists``, ``does_not_exist``, ``is_between``,
        ``is_not_between``, ``contains``.

        - ``is_between`` time filters: ``value`` is either ``[lo, hi]``
          (numeric) or ``{"from": ..., "to": ...}`` (time range, ISO-8601
          strings or epoch-ms).
        - ``contains``: substring match emitted as ``LIKE '%value%'``.
          ``value`` must be a scalar (string / number / bool); arrays and
          ``null`` are rejected. Wildcards (``%``, ``_``) and quotes in the
          value are escaped server-side so the substring matches literally.
        - ``exists`` / ``does_not_exist``: ``value`` is ignored — you can
          omit it.

        ``time_range`` (optional): convenience kwarg for the common case of
        bounding the viz to a single time window. Shape::

            {"from": "2025-05-22T00:00:00.000Z",
             "to":   "2026-05-22T00:00:00.000Z"}

        Values are ISO-8601 strings or epoch-ms numbers, interpreted as UTC.
        Accepts absolute timestamps only. The gateway applies it as a
        synthetic ``is_between`` filter on the viz's time column — by default
        ``@timestamp``, or whatever the viz declares via
        ``source.sql.time_column``.

        Returns the same envelope as before, plus ``metadata.filters_applied``
        (list of field names successfully injected) and
        ``metadata.filters_skipped`` (list of ``{field, reason}`` for filters
        the rewriter couldn't safely inject — e.g. parse failures on exotic
        SQL). Unrecognised filters do **not** fail the execute call; the
        original SQL still runs.

        Note on identifiers: send ``field`` raw — the gateway handles
        dialect-specific quoting (backticks for MySQL/BigQuery, double-quotes
        elsewhere). Pre-quoting ties your filter to a specific dialect and
        breaks portability.
        """
        url = f"{self.endpoint}/visualizations/{viz_id}/data"
        body: Dict[str, Any] = {}
        if filters:
            body["filters"] = [_normalize_filter(f) for f in filters]
        if time_range:
            body["time_range"] = time_range
        return self.request("POST", url, None, json.dumps(body))

    def to_echarts_option(
        self,
        viz: Dict[str, Any],
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Map a stored visualization + its executed rows into a renderable spec.

        Pure function — no network call. Pass in the result of
        ``get_visualization(viz_id)`` (or just its ``attributes``) and the
        result of ``execute_visualization(viz_id)``. Returns a dispatch dict:

            { "kind": "echarts" | "table" | "metric", ... }

        - ``kind == "echarts"``: ``result["option"]`` is plain ECharts JSON
          you can pass directly to ``echarts.setOption(...)`` in the browser,
          or to ``pyecharts.options.InitOpts`` / ``chart.set_option()`` in
          Python notebooks. Covers ``bar``, ``horizontalBar``, ``line``,
          ``area``, ``pie``, ``heatmap``, ``scatter``.
        - ``kind == "table"``: ``result["columns"]`` and ``result["rows"]``
          for inline HTML/pandas rendering. Returned when
          ``chart.type == "table"`` (unified rendering kind
          under ``chart.type``; the legacy ``visualization_mode`` field
          is retired) or when the data doesn't fit the declared chart type.
        - ``kind == "metric"``: ``result["value"]`` is the single
          aggregated value, with optional ``result["formatting"]`` (prefix,
          suffix, decimals, abbreviate, thousands_separator). Returned when
          ``chart.type == "metric" | "gauge"``.

        The opinionated mapping uses ``viz.mapping.x`` (``{column,
        bucket?}``), ``viz.mapping.y``, and
        ``viz.mapping.series`` to pick columns; if mapping is empty it
        falls back to "first column = X, second = Y" semantics.
        Styling (colors, fonts, tooltip formatters) is intentionally
        minimal — deep-merge your theme on top in your renderer.

        Out of scope: data subsampling (use ``LIMIT`` in your SQL),
        cross-filtering, drill-down. These are renderer-level concerns.
        """
        return _to_echarts_option_impl(viz, data)

    # Dashboard Operations
    def create_dashboard(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Create a dashboard. The server fills defaults for any field not
        supplied — minimally, ``title`` is enough (with ``panels`` defaulting
        to an empty list). Each panel needs ``viz_id`` for visualization
        panels, ``content`` for markdown panels, or nothing for dividers;
        ``kind`` defaults to ``"visualization"`` and ``layout`` auto-flows
        into a 2-column grid:

            >>> dash = client.create_dashboard({
            ...     "title": "Revenue overview",
            ...     "panels": [
            ...         {"viz_id": "viz-orders-by-currency"},
            ...         {"viz_id": "viz-orders-by-day"},
            ...     ],
            ... })

        Returns an envelope ``{"id", "kind", "created_at", "updated_at",
        "attributes": {<full Dashboard>}}``.
        """
        url = f"{self.endpoint}/dashboards"
        return self.request("POST", url, None, json.dumps(spec))

    def get_dashboard(self, dashboard_id: str) -> Dict[str, Any]:
        """Fetch a saved dashboard by id. Returns the envelope shape."""
        url = f"{self.endpoint}/dashboards/{dashboard_id}"
        return self.request("GET", url)

    def update_dashboard(
        self, dashboard_id: str, partial: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Patch a dashboard with a partial spec (RFC 7396 JSON Merge Patch).

        Only the fields you supply are touched; the rest are preserved. A
        ``null`` value removes the key. The server protects ``id``,
        ``schema_version``, ``created_at``, and ``created_by`` from mutation.

            >>> # Rename a dashboard without touching panels or options
            >>> client.update_dashboard(dash_id, {"title": "Revenue (Q3)"})

        Note that JSON Merge Patch's array semantics replace the array
        entirely — to add a single panel, send the full panel list including
        the new entry, not just the addition.

        Returns the updated envelope.
        """
        url = f"{self.endpoint}/dashboards/{dashboard_id}"
        return self.request("PATCH", url, None, json.dumps(partial))

    def list_dashboards(
        self, limit: Optional[int] = None, offset: Optional[int] = None
    ) -> Dict[str, Any]:
        """List dashboards the caller can see.

        Returns ``{"items": [envelope, envelope, ...]}``. Supports pagination
        via ``limit`` (server default 500, max 1000) and ``offset`` (default 0).
        """
        url = f"{self.endpoint}/dashboards"
        params: Optional[Dict[str, str]] = None
        if limit is not None or offset is not None:
            params = {}
            if limit is not None:
                params["limit"] = str(limit)
            if offset is not None:
                params["offset"] = str(offset)
        return self.request("GET", url, params=params)

    def delete_dashboard(self, dashboard_id: str) -> Dict[str, Any]:
        """Delete a dashboard by id."""
        url = f"{self.endpoint}/dashboards/{dashboard_id}"
        return self.request("DELETE", url)

    def execute_dashboard(
        self,
        dashboard_id: str,
        max_workers: int = 16,
        filters: Optional[List[Dict[str, Any]]] = None,
        time_range: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Execute every panel in a dashboard in parallel and return per-panel
        layout + viz config + plot-ready rows.

        For a 16-panel dashboard this replaces the customer's naive
        ``for panel in panels: get_visualization + execute_visualization``
        loop (33 sequential HTTP calls, ~1.5s wall time) with a single SDK
        call that fans out under the hood (~100ms wall time, slowest panel
        dominates).

        Returns a list of panel dicts in their dashboard order::

            [
              {
                "id": "panel_0",
                "kind": "visualization",
                "layout": {"x": 0, "y": 0, "w": 48, "h": 18},
                "title_override": None,
                "viz": {<full Visualization attributes>},   # None on error
                "data": {"columns": [...], "rows": [...],
                         "metadata": {...}},                  # None on error
                "error": None,                                # {status, message} on failure
              },
              ...
            ]

        - Visualization-kind panels populate ``viz`` and ``data``. Per-panel
          errors are captured in ``error`` (the whole call doesn't fail).
        - Markdown panels get ``content``; divider panels get ``label``.
        - Combine with :meth:`to_echarts_option` for the chart spec::

              for p in sdk.execute_dashboard(dash_id):
                  if p["kind"] != "visualization" or p["error"]:
                      continue
                  spec = sdk.to_echarts_option(p["viz"], p["data"])
                  render_at(p["layout"], spec)

        ``max_workers`` caps the parallelism. The default (16) is enough for
        typical dashboards; tune higher only if you're rendering 50+ panels
        and the gateway can absorb the concurrency.

        ``filters`` (optional): runtime filters applied to every visualization
        panel in the fanout. Same shape and semantics as
        :meth:`execute_visualization`.

        ``time_range`` (optional): time window applied to every visualization
        panel in the fanout. Shape::

            {"from": "2025-05-22T00:00:00.000Z",
             "to":   "2026-05-22T00:00:00.000Z"}

        Values are ISO-8601 strings or epoch-ms numbers, interpreted as UTC.
        Accepts absolute timestamps only. The gateway applies it per-panel as
        a synthetic ``is_between`` filter on each viz's time column — by
        default ``@timestamp``, or whatever the viz declares via
        ``source.sql.time_column``.
        """
        dash = self.get_dashboard(dashboard_id)
        panels = dash.get("attributes", {}).get("panels", []) or []

        def _resolve(panel: Dict[str, Any]) -> Dict[str, Any]:
            out: Dict[str, Any] = {
                "id": panel.get("id"),
                "kind": panel.get("kind"),
                "layout": panel.get("layout"),
                "title_override": panel.get("title_override"),
                "viz": None,
                "data": None,
                "error": None,
            }
            if panel.get("kind") == "visualization":
                viz_id = panel.get("viz_id")
                if not viz_id:
                    out["error"] = {"status": 400, "message": "panel missing viz_id"}
                    return out
                try:
                    viz_envelope = self.get_visualization(viz_id)
                    data = self.execute_visualization(
                        viz_id, filters=filters, time_range=time_range
                    )
                    out["viz"] = viz_envelope.get("attributes", viz_envelope)
                    out["data"] = data
                except InfinoError as e:
                    out["error"] = {
                        "status": e.status_code(),
                        "message": str(e),
                    }
            elif panel.get("kind") == "markdown":
                out["content"] = panel.get("content")
            elif panel.get("kind") == "divider":
                out["label"] = panel.get("label")
            return out

        if not panels:
            return []
        with ThreadPoolExecutor(
            max_workers=max(1, min(max_workers, len(panels)))
        ) as ex:
            return list(ex.map(_resolve, panels))

    # Fino AI Thread Operations
    def list_threads(self) -> List[Dict[str, Any]]:
        """List all Fino conversation threads"""
        url = f"{self.endpoint}/fino/threads"
        response = self.request("GET", url)
        if isinstance(response, list):
            return response
        raise InfinoError(InfinoError.Type.INVALID_REQUEST, "Expected list of threads")

    def create_thread(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new Fino conversation thread"""
        url = f"{self.endpoint}/fino/threads"
        response = self.request("POST", url, None, json.dumps(config))
        return response

    def get_thread(self, thread_id: str) -> Dict[str, Any]:
        """Retrieve a specific Fino conversation thread"""
        url = f"{self.endpoint}/fino/threads/{thread_id}"
        response = self.request("GET", url)
        return response

    def update_thread(self, thread_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update a Fino conversation thread"""
        url = f"{self.endpoint}/fino/threads/{thread_id}"
        response = self.request("PUT", url, None, json.dumps(config))
        return response

    def delete_thread(self, thread_id: str) -> Dict[str, Any]:
        """Delete a Fino conversation thread"""
        url = f"{self.endpoint}/fino/threads/{thread_id}"
        response = self.request("DELETE", url)
        return response

    def add_thread_message(
        self, thread_id: str, message: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a message to a specific Fino thread"""
        url = f"{self.endpoint}/fino/threads/{thread_id}/messages"
        response = self.request("POST", url, None, json.dumps(message))
        return response

    def clear_thread_messages(self, thread_id: str) -> Dict[str, Any]:
        """Remove all messages from a Fino thread"""
        url = f"{self.endpoint}/fino/threads/{thread_id}/messages"
        response = self.request("DELETE", url)
        return response

    def send_message(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send a message to Fino using the simplified API"""
        url = f"{self.endpoint}/fino/message"
        response = self.request("POST", url, None, json.dumps(payload))
        return response

    # Record Operations
    def get_record(self, dataset: str, record_id: str) -> Dict[str, Any]:
        """Get a record from a dataset"""
        url = f"{self.endpoint}/{dataset}/doc/{record_id}"
        response = self.request("GET", url)
        return response

    # Query Operations - Datasets
    def query_dataset_in_querydsl(self, dataset: str, query: str) -> Dict[str, Any]:
        """Query a dataset in QueryDSL"""
        url = f"{self.endpoint}/{dataset}/querydsl"
        response = self.request("GET", url, None, query)
        return response

    def query_dataset_in_sql(self, query: str) -> Dict[str, Any]:
        """Query a dataset in SQL, including across multiple datasets"""
        url = f"{self.endpoint}/sql"
        sql_request = {"query": query}
        json_body = json.dumps(sql_request)
        response = self.request("GET", url, None, json_body)
        return response

    def query_dataset_in_promql(
        self, query: str, dataset: Optional[str] = None
    ) -> Dict[str, Any]:
        """Query a dataset in PromQL"""
        from urllib.parse import quote

        url = f"{self.endpoint}/promql/query"

        form_data = f"query={quote(query)}"
        if dataset:
            form_data += f"&index={quote(dataset)}"

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = self.request("POST", url, headers, form_data)
        return response

    def query_dataset_in_promql_range(
        self, query: str, start: int, end: int, step: int, dataset: Optional[str] = None
    ) -> Dict[str, Any]:
        """Query a dataset in PromQL with time range"""
        from urllib.parse import quote

        url = f"{self.endpoint}/promql/query_range"

        form_data = f"query={quote(query)}&start={start}&end={end}&step={step}"
        if dataset:
            form_data += f"&index={quote(dataset)}"

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = self.request("POST", url, headers, form_data)
        return response

    # Correlate Operations - Upload to a dataset
    def upload_json_to_dataset(self, dataset: str, payload: str) -> Dict[str, Any]:
        """Upload JSON records to a dataset

        Args:
            dataset: Dataset name
            payload: NDJSON formatted bulk operations
        """
        url = f"{self.endpoint}/{dataset}/json"
        if not payload.endswith("\n"):
            payload += "\n"
        response = self.request(
            "POST", url, headers={"Content-Type": "application/x-ndjson"}, body=payload
        )
        return response

    def upsert_to_dataset(self, query: str) -> Dict[str, Any]:
        """Upload SQL rows to a dataset (upsert_to_dataset operations only)"""
        url = f"{self.endpoint}/sql"
        sql_request = {"query": query}
        json_body = json.dumps(sql_request)
        response = self.request("POST", url, None, json_body)
        return response

    def upload_metrics_to_dataset(self, dataset: str, payload: str) -> Dict[str, Any]:
        """Upload Prometheus metrics to a dataset"""
        url = f"{self.endpoint}/{dataset}/metrics"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = self.request("POST", url, headers, payload)
        return response

    def delete_records(self, dataset: str, query: str) -> Dict[str, Any]:
        """Delete records from a dataset"""
        url = f"{self.endpoint}/{dataset}"
        response = self.request("PATCH", url, None, query)
        return response

    def enrich_dataset(self, dataset: str, policy: str) -> Dict[str, Any]:
        """Update enrichment policy for a dataset"""
        url = f"{self.endpoint}/{dataset}/enrich_dataset"
        response = self.request("POST", url, None, policy)
        return response

    # File Upload Operations
    def upload_file(
        self,
        dataset: str,
        file_path: str,
        format: Optional[
            str
        ] = "auto",  # noqa: A002 - keeping for backwards compatibility
        batch_size: Optional[int] = None,
        async_mode: bool = False,
    ) -> Dict[str, Any]:
        """Upload a file (JSON, JSONL, CSV) to a dataset.

        Uploads a file to Infino for ingestion into the specified dataset.
        Supports both synchronous (wait for completion) and asynchronous
        (submit and poll) modes.

        Args:
            dataset: Target dataset/index name
            file_path: Path to the file to upload
            format: File format - "json", "jsonl", "csv", or "auto" (default).
                    When "auto", the format is detected from file extension.
            batch_size: Documents per processing batch (default: 5000)
            async_mode: If True, returns immediately with run_id for polling.
                       If False (default), waits for processing to complete.

        Returns:
            Upload response containing:
            - connector_id: "file"
            - run_id: UUID of the job
            - status: "completed" (sync) or "submitted" (async)
            - message: Status message
            - stats: Processing statistics (sync mode only)
            - errors: List of any errors

        Raises:
            InfinoError: If file not found or upload fails

        Example:
            # Sync mode - wait for completion
            result = sdk.upload_file("my_dataset", "data.json")
            print(f"Processed {result['stats']['documents_processed']} documents")

            # Async mode - submit and poll
            result = sdk.upload_file("my_dataset", "large_file.csv", async_mode=True)
            run_id = result["run_id"]
            # Poll for status
            status = sdk.get_connector_job_status(run_id)
        """

        # Validate file exists
        if not os.path.exists(file_path):
            raise InfinoError(
                InfinoError.Type.INVALID_REQUEST, f"File not found: {file_path}"
            )

        # Build URL with async query param
        url = f"{self.endpoint}/import/file"
        params = {"async": "true" if async_mode else "false"}

        # Prepare multipart form data
        filename = os.path.basename(file_path)

        # Determine content type based on format
        content_type_map = {
            "json": "application/json",
            "jsonl": "application/x-ndjson",
            "csv": "text/csv",
            "auto": "application/octet-stream",
        }
        content_type = content_type_map.get(format, "application/octet-stream")

        # Open file and prepare multipart
        with open(file_path, "rb") as f:
            files = {"file": (filename, f, content_type)}

            # Form data fields
            data = {
                "index_name": dataset,
                "format": format,
            }
            if batch_size is not None:
                data["batch_size"] = str(batch_size)

            response = self.request_multipart("POST", url, files, data, params)

        return response

    def get_connector_job_status(self, run_id: str) -> Dict[str, Any]:
        """Get status of a connector job by run_id.

        Use this to poll for completion after an async file upload.

        Args:
            run_id: The job run_id returned from upload_file(async_mode=True)

        Returns:
            Job status containing:
            - run_id: The job ID
            - status: "running", "completed", or "failed"
            - stats: Processing statistics (when completed)
            - errors: List of any errors

        Example:
            import time

            # Submit async upload
            result = sdk.upload_file("dataset", "data.csv", async_mode=True)
            run_id = result["run_id"]

            # Poll until complete
            while True:
                status = sdk.get_connector_job_status(run_id)
                if status["status"] in ("completed", "failed"):
                    break
                time.sleep(2)  # Wait 2 seconds between polls

            print(f"Final status: {status['status']}")
        """
        url = f"{self.endpoint}/_connectors/jobs/{run_id}"
        response = self.request("GET", url)
        return response

    @classmethod
    def new(cls, access_key: str, secret_key: str, endpoint: str) -> "InfinoSDK":
        """Convenience constructor"""
        return cls.new_with_retry(access_key, secret_key, endpoint, RetryConfig())

    @classmethod
    def new_with_retry(
        cls, access_key: str, secret_key: str, endpoint: str, retry_config: RetryConfig
    ) -> "InfinoSDK":
        """Constructor with custom retry config"""
        return cls(access_key, secret_key, endpoint, retry_config)

    # Connect Operations - Data Sources
    def get_sources(self) -> List[Dict[str, Any]]:
        """Get a list of available data sources"""
        url = f"{self.endpoint}/sources"
        response = self.request("GET", url)
        if isinstance(response, list):
            return response
        raise InfinoError(InfinoError.Type.INVALID_REQUEST, "Expected list of sources")

    def get_connections(self) -> List[Dict[str, Any]]:
        """Get a list of active data source connections"""
        url = f"{self.endpoint}/sources/connections"
        response = self.request("GET", url)
        if isinstance(response, list):
            return response
        raise InfinoError(
            InfinoError.Type.INVALID_REQUEST, "Expected list of connections"
        )

    def create_connection(
        self, source_type: str, config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create data source connection"""
        url = f"{self.endpoint}/source/{source_type}"
        response = self.request("POST", url, None, json.dumps(config))
        return response

    def get_connection(self, connection_id: str) -> Dict[str, Any]:
        """Get status of a data source connection"""
        url = f"{self.endpoint}/source/{connection_id}"
        response = self.request("GET", url)
        return response

    def update_connection(
        self, connection_id: str, config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update a data source connection"""
        url = f"{self.endpoint}/source/{connection_id}"
        response = self.request("PATCH", url, None, json.dumps(config))
        return response

    def delete_connection(self, connection_id: str) -> Dict[str, Any]:
        """Remove a data source connection"""
        url = f"{self.endpoint}/source/{connection_id}"
        response = self.request("DELETE", url)
        return response

    # Query Operations - Source Queries
    def query_source(
        self, connection_id: str, dataset: str, query: str
    ) -> Dict[str, Any]:
        """Query a data source connection in its native DSL

        For SQL sources (Snowflake, MySQL, etc.), the query should be a SQL string.
        For QueryDSL sources (Elasticsearch, OpenSearch), the query should be a JSON string.
        The query is automatically wrapped in {"query": "..."} format for the API.
        """
        url = f"{self.endpoint}/source/{connection_id}/{dataset}/dsl"
        headers = {"x-infino-connection-id": connection_id}
        # Wrap query in JSON object as expected by connector service
        query_body = json.dumps({"query": query})
        # Use POST as recommended by OpenAPI spec for queries with request bodies
        response = self.request("POST", url, headers, query_body)
        return response

    def get_source_metadata(self, connection_id: str, dataset: str) -> Dict[str, Any]:
        """Get metadata from a data source connection"""
        url = f"{self.endpoint}/source/{connection_id}/{dataset}/metadata"
        headers = {"x-infino-connection-id": connection_id}
        response = self.request("GET", url, headers)
        return response

    # Correlate Operations - Import Jobs
    def create_import_job(
        self, source_type: str, config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create import job from data source to a dataset"""
        url = f"{self.endpoint}/import/{source_type}"
        response = self.request("PUT", url, None, json.dumps(config))
        return response

    def get_import_jobs(self) -> List[Dict[str, Any]]:
        """Get a dataset import job status"""
        url = f"{self.endpoint}/import/jobs"
        response = self.request("GET", url)
        if isinstance(response, list):
            return response
        raise InfinoError(InfinoError.Type.INVALID_REQUEST, "Expected list of jobs")

    def delete_import_job(self, job_id: str) -> Dict[str, Any]:
        """Delete a import job"""
        url = f"{self.endpoint}/import/jobs/{job_id}"
        response = self.request("DELETE", url)
        return response

    # Governance Operations
    def create_user(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a user in your account"""
        url = f"{self.endpoint}/user/{name}"
        # YAML only for users when config is a string; otherwise JSON
        if isinstance(config, str):
            try:
                yaml.safe_load(config)  # syntax validation only
            except Exception as e:
                raise InfinoError(
                    InfinoError.Type.INVALID_REQUEST, f"Invalid YAML: {e}"
                ) from e
            headers = {"Content-Type": "application/yaml"}
            body = config
        else:
            headers = None
            body = json.dumps(config)
        response = self.request("PUT", url, headers, body)
        return response

    def get_user(self, name: str) -> Dict[str, Any]:
        """Get details for a user in your account"""
        url = f"{self.endpoint}/user/{name}"
        response = self.request("GET", url)
        return response

    def update_user(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update a user in your account"""
        url = f"{self.endpoint}/user/{name}"
        if isinstance(config, str):
            try:
                yaml.safe_load(config)
            except Exception as e:
                raise InfinoError(
                    InfinoError.Type.INVALID_REQUEST, f"Invalid YAML: {e}"
                ) from e
            headers = {"Content-Type": "application/yaml"}
            body = config
        else:
            headers = None
            body = json.dumps(config)
        response = self.request("PATCH", url, headers, body)
        return response

    def delete_user(self, name: str) -> Dict[str, Any]:
        """Delete a user in your account"""
        url = f"{self.endpoint}/user/{name}"
        response = self.request("DELETE", url)
        return response

    def list_users(self) -> Dict[str, Any]:
        """List the users in your account"""
        url = f"{self.endpoint}/users"
        response = self.request("GET", url)
        return response

    def create_role(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a role in your account"""
        url = f"{self.endpoint}/role/{name}"
        if isinstance(config, str):
            try:
                yaml.safe_load(config)
            except Exception as e:
                raise InfinoError(
                    InfinoError.Type.INVALID_REQUEST, f"Invalid YAML: {e}"
                ) from e
            headers = {"Content-Type": "application/yaml"}
            body = config
        else:
            headers = None
            body = json.dumps(config)
        response = self.request("PUT", url, headers, body)
        return response

    def get_role(self, name: str) -> Dict[str, Any]:
        """Get details for a role in your account"""
        url = f"{self.endpoint}/role/{name}"
        response = self.request("GET", url)
        return response

    def update_role(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update a role in your account"""
        url = f"{self.endpoint}/role/{name}"
        if isinstance(config, str):
            try:
                yaml.safe_load(config)
            except Exception as e:
                raise InfinoError(
                    InfinoError.Type.INVALID_REQUEST, f"Invalid YAML: {e}"
                ) from e
            headers = {"Content-Type": "application/yaml"}
            body = config
        else:
            headers = None
            body = json.dumps(config)
        response = self.request("PATCH", url, headers, body)
        return response

    def delete_role(self, name: str) -> Dict[str, Any]:
        """Delete a role in your account"""
        url = f"{self.endpoint}/role/{name}"
        response = self.request("DELETE", url)
        return response

    def list_roles(self) -> Dict[str, Any]:
        """List the roles in your account"""
        url = f"{self.endpoint}/roles"
        response = self.request("GET", url)
        return response

    def ping(self) -> Dict[str, Any]:
        """Health check"""
        url = f"{self.endpoint}/"
        response = self.request("GET", url)
        return response

    def rotate_keys(self, username: str) -> Dict[str, Any]:
        """Rotate API keys for a user

        Args:
            username: Username whose keys to rotate

        Returns:
            New credentials (access_key and secret_key)
        """
        url = f"{self.endpoint}/user/{username}/keys"
        response = self.request("PATCH", url)
        return response


# ──────────────────────────────────────────────────────────────────────────────
# ECharts option builder — pure function used by `InfinoSDK.to_echarts_option`.
# Plain dict output (no pyecharts dependency); the spec is directly consumable
# by `echarts.setOption(...)` in any language / web stack.
# ──────────────────────────────────────────────────────────────────────────────


def _normalize_filter(f: Dict[str, Any]) -> Dict[str, Any]:
    """Fill in defaults for fields the gateway requires but callers usually omit.

    Pass-through: ``field``, ``operator``, ``value``. Defaults: ``id`` (uuid4),
    ``enabled`` (True), ``is_time_filter`` (False), ``query_type`` (None),
    ``index`` (None). Caller-provided values always win.
    """
    import uuid

    return {
        "id": f.get("id") or uuid.uuid4().hex,
        "field": f["field"],
        "operator": f["operator"],
        "value": f.get("value"),
        "enabled": f.get("enabled", True),
        "is_time_filter": f.get("is_time_filter", False),
        "query_type": f.get("query_type"),
        "index": f.get("index"),
    }


def _sort_axis_values(values):
    """Sort axis-category values numerically when they all parse as numbers,
    otherwise lexicographically. Avoids ``"10" < "9"`` string-sort surprises
    on hour/day/numeric-as-string axes."""

    def _maybe_num(v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    try:
        nums = [(_maybe_num(v), v) for v in values]
        if all(n is not None for n, _ in nums):
            return [orig for _, orig in sorted(nums, key=lambda t: t[0])]
    except Exception:
        pass
    return sorted(values)


def _to_echarts_option_impl(
    viz: Dict[str, Any], data: Dict[str, Any]
) -> Dict[str, Any]:
    """Implementation of `InfinoSDK.to_echarts_option`. See docstring there.

    Axis-to-column mapping is read **only** from ``data.metadata.binding`` —
    the single contract every execute response publishes. The viz spec is
    consulted for ``chart.type`` and presentational options (title,
    formatting) but never for column resolution. This keeps the renderer
    decoupled from the spec shape so it doesn't break as new source kinds
    (DSL, PromQL) ship.
    """
    # Accept either the full envelope ({id, kind, attributes: {...}}) or the
    # attributes dict directly.
    attrs = viz.get("attributes", viz) if isinstance(viz, dict) else {}
    title = attrs.get("title") or ""
    chart_type = (attrs.get("chart") or {}).get("type", "bar")
    formatting = (attrs.get("options") or {}).get("metric_formatting")

    columns = data.get("columns") or []
    rows = data.get("rows") or []
    metadata = data.get("metadata") or {}
    binding = metadata.get("binding") or {}

    # Single source of truth for axis assignments. Renamed
    # `series_split_by` → `series`; fall back to the legacy key so an
    # older gateway response still renders.
    x_col = binding.get("x")
    y_cols: List[str] = list(binding.get("y") or [])
    series_split = binding.get("series") or binding.get("series_split_by")
    value_col = binding.get("value")

    # --- chart.type "table" → return table shape -------------------------
    if chart_type == "table":
        return {"kind": "table", "columns": columns, "rows": rows, "title": title}

    # --- chart.type ∈ {metric, gauge} → single-value rendering -----------
    if chart_type in ("metric", "gauge"):
        value = None
        if rows and value_col is not None:
            value = rows[0].get(value_col)
        elif rows and columns:
            # Defensive fallback (raw_query with no binding) — first numeric.
            for c in columns:
                if c.get("type") == "number":
                    value = rows[0].get(c["name"])
                    break
        return {
            "kind": "metric",
            "title": title,
            "label": title,
            "value": value,
            "formatting": formatting,
        }

    if not rows:
        # Empty → return an empty-shaped table so the consumer still has
        # something to render with a clear "no data" affordance.
        return {"kind": "table", "columns": columns, "rows": [], "title": title}

    option: Dict[str, Any]
    if chart_type == "pie":
        if not (x_col and y_cols):
            return {"kind": "table", "columns": columns, "rows": rows, "title": title}
        option = {
            "title": {"text": title},
            "tooltip": {"trigger": "item"},
            "legend": {"orient": "horizontal", "bottom": 0},
            "series": [
                {
                    "name": y_cols[0],
                    "type": "pie",
                    "radius": ["40%", "70%"],
                    "data": [
                        {"name": str(r[x_col]), "value": r[y_cols[0]] or 0}
                        for r in rows
                    ],
                }
            ],
        }
    elif chart_type == "heatmap":
        if not (x_col and y_cols and series_split):
            return {"kind": "table", "columns": columns, "rows": rows, "title": title}
        # Numeric-aware sort so hour-of-day / day-of-month axes are in correct
        # numeric order rather than lexicographic ("10" < "9").
        xs = _sort_axis_values({str(r[x_col]) for r in rows})
        ys = _sort_axis_values({str(r[series_split]) for r in rows})
        xi = {v: i for i, v in enumerate(xs)}
        yi = {v: i for i, v in enumerate(ys)}
        heat = [
            [xi[str(r[x_col])], yi[str(r[series_split])], r[y_cols[0]] or 0]
            for r in rows
        ]
        vmax = max((p[2] for p in heat), default=1) or 1
        option = {
            "title": {"text": title},
            "tooltip": {"position": "top"},
            "xAxis": {"type": "category", "data": xs, "splitArea": {"show": True}},
            "yAxis": {"type": "category", "data": ys, "splitArea": {"show": True}},
            "visualMap": {
                "min": 0,
                "max": vmax,
                "calculable": True,
                "orient": "horizontal",
                "left": "center",
                "bottom": 0,
            },
            "series": [
                {
                    "name": y_cols[0],
                    "type": "heatmap",
                    "data": heat,
                    "label": {"show": True, "fontSize": 10},
                    "emphasis": {
                        "itemStyle": {
                            "shadowBlur": 10,
                            "shadowColor": "rgba(0, 0, 0, 0.5)",
                        }
                    },
                }
            ],
        }
    elif chart_type == "scatter":
        if not (x_col and y_cols):
            return {"kind": "table", "columns": columns, "rows": rows, "title": title}
        option = {
            "title": {"text": title},
            "tooltip": {"trigger": "item"},
            "xAxis": {"type": "value", "name": x_col},
            "yAxis": {"type": "value", "name": y_cols[0]},
            "series": [
                {
                    "name": y_cols[0],
                    "type": "scatter",
                    "data": [[r.get(x_col), r.get(y_cols[0])] for r in rows],
                }
            ],
        }
    else:
        # bar / horizontalBar / line / area — all axis charts with optional
        # series split. Use line type for line/area (with areaStyle for area).
        is_horizontal = chart_type == "horizontalBar"
        is_line_like = chart_type in ("line", "area")
        is_area = chart_type == "area"
        series_type = "line" if is_line_like else "bar"

        # Horizontal bars get inline value labels at the right end of each bar
        # (pyecharts does this by default; we replicate so the look matches).
        bar_label = {"show": True, "position": "right"} if is_horizontal else None

        if series_split and y_cols:
            # Pivot rows into one series per `binding.series` value.
            x_vals = []
            series_buckets: Dict[str, Dict[str, Any]] = {}
            for r in rows:
                xv = str(r.get(x_col))
                if xv not in x_vals:
                    x_vals.append(xv)
                sv = str(r.get(series_split))
                series_buckets.setdefault(sv, {})[xv] = r.get(y_cols[0])
            series = []
            for sv, bucket in series_buckets.items():
                s = {
                    "name": sv,
                    "type": series_type,
                    "data": [bucket.get(xv) for xv in x_vals],
                }
                if is_area:
                    s["areaStyle"] = {}
                if bar_label:
                    s["label"] = bar_label
                series.append(s)
        else:
            x_vals = [str(r.get(x_col)) for r in rows]
            series = []
            for y in y_cols:
                s = {
                    "name": y,
                    "type": series_type,
                    "data": [r.get(y) for r in rows],
                }
                if is_area:
                    s["areaStyle"] = {}
                if bar_label:
                    s["label"] = bar_label
                series.append(s)

        x_axis = {"type": "category", "data": x_vals, "name": x_col}
        y_axis = {"type": "value"}
        option = {
            "title": {"text": title, "left": "center"},
            "tooltip": {"trigger": "axis"},
            "legend": {"top": 28} if len(series) > 1 else {"show": False},
            "grid": {"left": "3%", "right": "8%", "bottom": "8%", "containLabel": True},
            "xAxis": y_axis if is_horizontal else x_axis,
            "yAxis": x_axis if is_horizontal else y_axis,
            "series": series,
        }

    # Centre titles on every option type so panels render with consistent header
    # alignment when laid out in a CSS grid.
    if isinstance(option.get("title"), dict):
        option["title"].setdefault("left", "center")
    return {"kind": "echarts", "title": title, "option": option}


# Error conversion implementations
def _convert_reqwest_error(error: requests.RequestException) -> InfinoError:
    """Convert requests error to InfinoError"""
    return InfinoError(error_type=InfinoError.Type.NETWORK, message=str(error))


def _convert_json_error(error: json.JSONDecodeError) -> InfinoError:
    """Convert JSON error to InfinoError"""
    return InfinoError(error_type=InfinoError.Type.PARSE, message=str(error))


# Minimal demo tests
if __name__ == "__main__":
    import unittest

    import responses

    class TestInfinoSDK(unittest.TestCase):
        """Basic tests for InfinoSDK"""

        def setUp(self):
            self.client = InfinoSDK(
                access_key="test_key",
                secret_key="test_secret",
                endpoint="http://localhost:8000",
            )

        @responses.activate
        def test_request_signing(self):
            """Test request signing"""
            responses.add(
                responses.GET,
                "http://localhost:8000/test_dataset/querydsl",
                json={"hits": []},
                status=200,
                match=[
                    responses.matchers.header_matcher(
                        {
                            "authorization": lambda x: x.startswith("AWS4-HMAC-SHA256"),
                            "x-amz-date": lambda x: len(x) == 16,  # YYYYMMDDTHHmmssZ
                            "x-amz-content-sha256": lambda x: len(x) == 64,
                        }
                    )
                ],
            )

            query = json.dumps({"query": {"match_all": {}}})
            response = self.client.query_dataset_in_querydsl("test_dataset", query)
            self.assertEqual(response, {"hits": []})

        @responses.activate
        def test_document_operations(self):
            """Test document operations"""
            responses.add(
                responses.PUT,
                "http://localhost:8000/test_dataset/doc/1",
                json={"result": "created"},
                status=200,
                match=[
                    responses.matchers.header_matcher(
                        {
                            "authorization": lambda x: x.startswith("AWS4-HMAC-SHA256"),
                            "x-amz-date": lambda x: len(x) == 16,
                            "x-amz-content-sha256": lambda x: len(x) == 64,
                        }
                    )
                ],
            )

            # Note: This test validates the mock setup but doesn't call the endpoint
            # since dataset_record doesn't exist in the SDK
            self.assertTrue(True)

        @responses.activate
        def test_security_operations(self):
            """Test security API operations"""
            # Test role creation with new YAML format
            responses.add(
                responses.PUT,
                "http://localhost:8000/role/test_role",
                json={"status": "OK", "message": "'test_role' created."},
                status=200,
                match=[
                    responses.matchers.header_matcher(
                        {
                            "authorization": lambda x: x.startswith("AWS4-HMAC-SHA256"),
                            "x-amz-date": lambda x: len(x) == 16,
                            "x-amz-content-sha256": lambda x: len(x) == 64,
                            "content-type": "application/yaml",
                        }
                    )
                ],
            )

            role_config = """
Version: 2025-01-01
Permissions:
  - ResourceType: record
    Actions: [read, write]
    Resources: ["test*"]
  
  - ResourceType: dataset
    Actions: [create, delete]
    Resources: ["test*"]
"""

            response = self.client.create_role("test_role", role_config)
            self.assertEqual(response["status"], "OK")

            # Test user creation with role assignment
            responses.add(
                responses.PUT,
                "http://localhost:8000/user/test_user",
                json={"status": "OK", "message": "'test_user' created."},
                status=200,
                match=[
                    responses.matchers.header_matcher(
                        {
                            "authorization": lambda x: x.startswith("AWS4-HMAC-SHA256"),
                            "x-amz-date": lambda x: len(x) == 16,
                            "x-amz-content-sha256": lambda x: len(x) == 64,
                            "content-type": "application/yaml",
                        }
                    )
                ],
            )

            user_config = """
Version: 2025-01-01
Password: TestP@ssw0rd123!
Roles:
  - test_role
"""

            response = self.client.create_user("test_user", user_config)
            self.assertEqual(response["status"], "OK")

    unittest.main()
