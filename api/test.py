# api/mx.py

from modules.auth import secure_auth
import time
import jwt

# ----------------------------------------------------------
# Helper to print test results nicely
# ----------------------------------------------------------
def print_result(test_name, result, extra=None):
    print(f"--- {test_name} ---")
    print("Result:", result)
    if extra:
        print("Extra:", extra)
    print("\n")

# ----------------------------------------------------------
# Test Case 1: Successful Login
# ----------------------------------------------------------
login_result = secure_auth.login("testuser", "test1234")
print_result("Test Case 1: Successful Login", login_result.success, login_result.token)

# ----------------------------------------------------------
# Test Case 2: Verify Token
# ----------------------------------------------------------
if login_result.success and login_result.token:
    try:
        decoded = secure_auth.verify_token(login_result.token)
        print_result("Test Case 2: Verify Token", True, decoded)
    except jwt.PyJWTError as e:
        print_result("Test Case 2: Verify Token", False, str(e))

# ----------------------------------------------------------
# Test Case 3: Invalid Password
# ----------------------------------------------------------
invalid_login = secure_auth.login("testuser", "wrongpassword")
print_result("Test Case 3: Invalid Password", invalid_login.success, invalid_login.message)

# ----------------------------------------------------------
# Test Case 4: Locked Account
# ----------------------------------------------------------
# Simulate multiple failed attempts
for _ in range(secure_auth.LOCKOUT_THRESHOLD):
    secure_auth.login("testuser", "wrongpassword")

locked_result = secure_auth.login("testuser", "test1234")
print_result("Test Case 4: Locked Account", locked_result.success, locked_result.message)

# ----------------------------------------------------------
# Test Case 5: Token Tampering
# ----------------------------------------------------------
if login_result.success and login_result.token:
    tampered_token = login_result.token[:-1] + ('A' if login_result.token[-1] != 'A' else 'B')
    try:
        secure_auth.verify_token(tampered_token)
        print_result("Test Case 5: Token Tampering", False, "No error raised")
    except jwt.exceptions.InvalidSignatureError as e:
        print_result("Test Case 5: Token Tampering", True, "InvalidSignatureError caught")

# ----------------------------------------------------------
# Test Case 6: Expired Token
# ----------------------------------------------------------
# Generate short-lived token for test
short_exp_token = secure_auth.login("testuser", "test1234").token
decoded_payload = jwt.decode(short_exp_token, secure_auth.PUBLIC_KEY, algorithms=["RS256"], options={"verify_exp": False})
decoded_payload["exp"] = int(time.time()) - 10  # expired 10 seconds ago
expired_token = jwt.encode(decoded_payload, secure_auth.PRIVATE_KEY, algorithm="RS256")

try:
    secure_auth.verify_token(expired_token)
    print_result("Test Case 6: Expired Token", False, "No error raised")
except jwt.exceptions.ExpiredSignatureError:
    print_result("Test Case 6: Expired Token", True, "ExpiredSignatureError caught")
