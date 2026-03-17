"""
Tests for governance operations: role mapping CRUD, update_user_password,
get_user_account_info, get_user_auth_info, generate_user_token
"""

import json
from unittest.mock import Mock

import pytest

from infino_sdk.lib import InfinoError, InfinoSDK


class TestRoleMappings:
    """Test role mapping CRUD operations"""

    def test_create_role_mapping(self, mock_sdk):
        sdk, _ = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = json.dumps(
            {"status": "CREATED", "message": "'my_mapping' created."}
        )
        sdk.session.request.return_value = mock_response

        config = {
            "backend_roles": ["admin_backend"],
            "roles": ["all_access"],
            "users": ["admin"],
        }
        result = sdk.create_role_mapping("my_mapping", config)

        assert result["status"] == "CREATED"
        call_args = sdk.session.request.call_args
        assert call_args.kwargs["method"] == "PUT"
        assert "/rolemapping/my_mapping" in call_args.kwargs["url"]

    def test_get_role_mapping(self, mock_sdk):
        sdk, _ = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = json.dumps(
            {
                "my_mapping": {
                    "backend_roles": ["admin_backend"],
                    "roles": ["all_access"],
                }
            }
        )
        sdk.session.request.return_value = mock_response

        result = sdk.get_role_mapping("my_mapping")

        assert "my_mapping" in result
        call_args = sdk.session.request.call_args
        assert call_args.kwargs["method"] == "GET"

    def test_update_role_mapping(self, mock_sdk):
        sdk, _ = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = json.dumps(
            {"status": "OK", "message": "'my_mapping' updated."}
        )
        sdk.session.request.return_value = mock_response

        config = {"roles": ["read_only"]}
        result = sdk.update_role_mapping("my_mapping", config)

        assert result["status"] == "OK"
        call_args = sdk.session.request.call_args
        assert call_args.kwargs["method"] == "PATCH"

    def test_delete_role_mapping(self, mock_sdk):
        sdk, _ = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = json.dumps(
            {"status": "OK", "message": "'my_mapping' deleted."}
        )
        sdk.session.request.return_value = mock_response

        result = sdk.delete_role_mapping("my_mapping")

        assert result["status"] == "OK"
        call_args = sdk.session.request.call_args
        assert call_args.kwargs["method"] == "DELETE"
        assert "/rolemapping/my_mapping" in call_args.kwargs["url"]

    def test_list_role_mappings(self, mock_sdk):
        sdk, _ = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = json.dumps(
            {
                "mapping_a": {"roles": ["role1"]},
                "mapping_b": {"roles": ["role2"]},
            }
        )
        sdk.session.request.return_value = mock_response

        result = sdk.list_role_mappings()

        assert "mapping_a" in result
        assert "mapping_b" in result
        call_args = sdk.session.request.call_args
        assert call_args.kwargs["url"].endswith("/rolemappings")


class TestAccountAuth:
    """Test account and auth operations"""

    def test_update_user_password(self, mock_sdk):
        sdk, _ = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = json.dumps(
            {"status": "OK", "message": "Password updated."}
        )
        sdk.session.request.return_value = mock_response

        result = sdk.update_user_password("alice", "NewP@ssw0rd!")

        assert result["status"] == "OK"
        call_args = sdk.session.request.call_args
        assert call_args.kwargs["method"] == "PATCH"
        assert "/user/alice/password" in call_args.kwargs["url"]
        body = json.loads(call_args.kwargs["data"])
        assert body["password"] == "NewP@ssw0rd!"

    def test_get_user_account_info(self, mock_sdk):
        sdk, _ = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = json.dumps(
            {
                "account_id": "acc-001",
                "name": "Test Account",
                "storage_quota": {"used_bytes": 1024, "max_bytes": 1048576},
            }
        )
        sdk.session.request.return_value = mock_response

        result = sdk.get_user_account_info()

        assert result["account_id"] == "acc-001"
        call_args = sdk.session.request.call_args
        assert call_args.kwargs["method"] == "GET"
        assert call_args.kwargs["url"].endswith("/account")

    def test_get_user_auth_info(self, mock_sdk):
        sdk, _ = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = json.dumps(
            {
                "username": "alice",
                "roles": ["admin", "analyst"],
                "account_id": "acc-001",
            }
        )
        sdk.session.request.return_value = mock_response

        result = sdk.get_user_auth_info()

        assert result["username"] == "alice"
        assert "admin" in result["roles"]
        call_args = sdk.session.request.call_args
        assert call_args.kwargs["url"].endswith("/user/auth")

    def test_generate_user_token(self, mock_sdk):
        sdk, _ = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = json.dumps(
            {"token": "eyJhbGciOi...", "expires_in_days": 30}
        )
        sdk.session.request.return_value = mock_response

        result = sdk.generate_user_token("alice", duration_days=30)

        assert "token" in result
        call_args = sdk.session.request.call_args
        assert call_args.kwargs["method"] == "POST"
        assert "/user/alice/token" in call_args.kwargs["url"]
        body = json.loads(call_args.kwargs["data"])
        assert body["duration_days"] == 30

    def test_generate_user_token_custom_duration(self, mock_sdk):
        sdk, _ = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = json.dumps(
            {"token": "eyJhbGciOi...", "expires_in_days": 90}
        )
        sdk.session.request.return_value = mock_response

        result = sdk.generate_user_token("bob", duration_days=90)

        assert result["expires_in_days"] == 90
        body = json.loads(sdk.session.request.call_args.kwargs["data"])
        assert body["duration_days"] == 90
