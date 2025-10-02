"""
User and Security Management with Infino SDK

This example demonstrates:
- Creating and managing users
- Role creation and management
- Role mapping
- API key rotation
"""

import os
from infino_sdk import InfinoSDK, InfinoError


def main():
    access_key = os.getenv("INFINO_ACCESS_KEY", "your_access_key")
    secret_key = os.getenv("INFINO_SECRET_KEY", "your_secret_key")
    endpoint = os.getenv("INFINO_ENDPOINT", "https://api.infino.ws")

    sdk = InfinoSDK(access_key, secret_key, endpoint)
    print("✅ Connected to Infino")
        
        # Create a custom role
        print("\n👤 Creating custom role...")
        role_name = "data_analyst"
        role_config = {
            "cluster_permissions": [
                "cluster:monitor/main",
                "cluster:monitor/health"
            ],
            "index_permissions": [
                {
                    "index_patterns": ["analytics*", "logs*"],
                    "allowed_actions": [
                        "indices:data/read/search",
                        "indices:data/read/msearch",
                        "indices:data/read/get",
                        "indices:monitor/stats"
                    ]
                },
                {
                    "index_patterns": ["reports*"],
                    "allowed_actions": [
                        "indices:data/read/*",
                        "indices:data/write/index",
                        "indices:data/write/update"
                    ]
                }
            ]
        }
        
    try:
        sdk.create_role(role_name, role_config)
        print(f"✅ Created role: {role_name}")
    except InfinoError as e:
        if e.status_code() == 409:
            print(f"ℹ️  Role {role_name} already exists")
        else:
            raise

        # Create a user
        print("\n👤 Creating user...")
        username = "john_analyst"
        user_config = {
            "password": "SecureP@ssw0rd123!",
            "backend_roles": ["analyst"],
            "attributes": {
                "department": "analytics",
                "team": "data-science",
                "email": "john@company.com"
            }
        }
        
    try:
        sdk.create_user(username, user_config)
        print(f"✅ Created user: {username}")
    except InfinoError as e:
        if e.status_code() == 409:
            print(f"ℹ️  User {username} already exists")
        else:
            raise

        # Get user details
    print(f"\n🔍 Fetching user details...")
    try:
        user = sdk.get_user(username)
        print(f"User: {username}")
        print(f"  Backend roles: {user.get(username, {}).get('backend_roles', [])}")
        print(f"  Attributes: {user.get(username, {}).get('attributes', {})}")
    except InfinoError as e:
        print(f"❌ Failed to get user: {e.message}")

        # Create role mapping
        print(f"\n🔗 Creating role mapping...")
        mapping_name = "analyst_mapping"
        mapping_config = {
            "users": [username],
            "backend_roles": ["analyst", "data-team"],
            "hosts": ["*"],
            "description": "Mapping for data analyst team"
        }
        
    try:
        sdk.create_role_mapping(mapping_name, mapping_config)
        print(f"✅ Created role mapping: {mapping_name}")
    except InfinoError as e:
        if e.status_code() == 409:
            print(f"ℹ️  Mapping {mapping_name} already exists")
        else:
            raise

        # List all users
    print(f"\n📋 Listing all users...")
    try:
        users = sdk.list_users()
        print(f"Total users: {len(users)}")
        for user_name in list(users.keys())[:5]:
            print(f"  - {user_name}")
    except InfinoError as e:
        print(f"❌ Failed to list users: {e.message}")

        # List all roles
    print(f"\n📋 Listing all roles...")
    try:
        roles = sdk.list_roles()
        print(f"Total roles: {len(roles)}")
        for role_name in list(roles.keys())[:5]:
            print(f"  - {role_name}")
    except InfinoError as e:
        print(f"❌ Failed to list roles: {e.message}")

        # List role mappings
    print(f"\n📋 Listing role mappings...")
    try:
        mappings = sdk.list_role_mappings()
        print(f"Total mappings: {len(mappings)}")
        for mapping_name in list(mappings.keys())[:5]:
            print(f"  - {mapping_name}")
    except InfinoError as e:
        print(f"❌ Failed to list mappings: {e.message}")

        # Update user password
    print(f"\n🔄 Updating user password...")
    try:
        update_config = {
            "password": "NewSecureP@ssw0rd456!"
        }
        sdk.update_user(username, update_config)
        print(f"✅ Updated password for {username}")
    except InfinoError as e:
        print(f"❌ Failed to update user: {e.message}")

        # Rotate API keys
    print(f"\n🔑 Rotating API keys for user...")
    try:
        new_creds = sdk.rotate_api_keys(username)
        print(f"✅ New credentials generated:")
        print(f"  Access Key: {new_creds.get('access_key', 'N/A')[:20]}...")
        print(f"  Secret Key: {new_creds.get('secret_key', 'N/A')[:20]}...")
        print(f"  ⚠️  Save these credentials securely!")
    except InfinoError as e:
        print(f"❌ Failed to rotate keys: {e.message}")

        # Get current user's account info
    print(f"\n👤 Getting current user account info...")
    try:
        account_info = sdk.get_user_account_info()
        print(f"Current user: {account_info.get('user_name', 'N/A')}")
        print(f"Backend roles: {account_info.get('backend_roles', [])}")
        print(f"Roles: {account_info.get('roles', [])}")
    except InfinoError as e:
        print(f"❌ Failed to get account info: {e.message}")

        # Cleanup (optional - uncomment to clean up test resources)
        # print(f"\n🧹 Cleanup...")
        # try:
        #     await sdk.delete_role_mapping(mapping_name)
        #     print(f"✅ Deleted role mapping: {mapping_name}")
        # except InfinoError as e:
        #     print(f"⚠️  Could not delete mapping: {e.message}")
        
        # try:
        #     await sdk.delete_user(username)
        #     print(f"✅ Deleted user: {username}")
        # except InfinoError as e:
        #     print(f"⚠️  Could not delete user: {e.message}")
        
        # try:
        #     await sdk.delete_role(role_name)
        #     print(f"✅ Deleted role: {role_name}")
        # except InfinoError as e:
        #     print(f"⚠️  Could not delete role: {e.message}")


if __name__ == "__main__":
    main()
