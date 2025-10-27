"""
User and Security Management with Infino SDK

This example demonstrates:
- Creating and managing users
- Role creation and management
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
    role_config = """
Version: 2025-01-01
Permissions:
  - ResourceType: record
    Actions: [read]
    Resources: ["analytics-*", "logs-*"]
    Fields:
      Mask:
        secret: redact
      Deny:
        - password
        - api_key
  
  - ResourceType: record
    Actions: [read, write]
    Resources: ["reports-*"]
  
  - ResourceType: metadata
    Actions: [read]
    Resources: ["*"]
"""
        
    try:
        sdk.create_role(role_name, role_config)
        print(f"✅ Created role: {role_name}")
    except InfinoError as e:
        if e.status_code() == 409:
            print(f"ℹ️  Role {role_name} already exists")
        else:
            raise

        # Create a user (simplified YAML)
        print("\n👤 Creating user...")
        username = "john_analyst"
        user_config = """
Version: 2025-01-01
Password: SecureP@ssw0rd123!
Roles:
  - data_analyst
"""
        
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
        # Simplified response typically includes 'Roles' and may include 'account_id'
        obj = user.get(username, user)
        roles = obj.get('Roles') or obj.get('roles') or []
        account_id = obj.get('account_id') or obj.get('AccountId')
        print(f"  Roles: {roles}")
        if account_id:
            print(f"  Account ID: {account_id}")
    except InfinoError as e:
        print(f"❌ Failed to get user: {e.message}")

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

        # Update user password
    print(f"\n🔄 Updating user password...")
    try:
        update_config = """
Version: 2025-01-01
Password: NewSecureP@ssw0rd456!
Roles:
  - data_analyst
"""
        sdk.update_user(username, update_config)
        print(f"✅ Updated password for {username}")
    except InfinoError as e:
        print(f"❌ Failed to update user: {e.message}")

        # Rotate API keys
    print(f"\n🔑 Rotating API keys...")
    try:
        new_creds = sdk.rotate_keys()
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
        print(f"Roles: {account_info.get('roles', [])}")
    except InfinoError as e:
        print(f"❌ Failed to get account info: {e.message}")

        # Cleanup (optional - uncomment to clean up test resources)
        # print(f"\n🧹 Cleanup...")
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
