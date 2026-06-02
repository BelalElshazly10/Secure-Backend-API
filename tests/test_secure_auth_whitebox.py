# tests/test_secure_auth.py
import pytest
import time
from unittest.mock import patch

#from modules.auth.secure_auth import login, register, USERS, LOCKOUT_THRESHOLD, LOCKOUT_WINDOW
from modules.auth.secure_auth import login, register, verify_token, USERS, LOCKOUT_THRESHOLD, LOCKOUT_WINDOW

# ----------------------------------------------------------
# Setup Fixture
# ----------------------------------------------------------
@pytest.fixture(autouse=True)
def setup_database():
    """
    This runs automatically before EVERY test.
    It clears the memory and registers a fresh baseline user.
    """
    USERS.clear()
    register("target_user", "CorrectPassword123")
    yield  # The test runs here

# ----------------------------------------------------------
# White Box Tests
# ----------------------------------------------------------

def test_login_invalid_user():
    """Path 1: The user does not exist in the dictionary."""
    result = login("ghost_user", "AnyPassword")
    
    assert not result.success
    assert result.message == "Invalid credentials"


def test_login_success():
    """Path 2: Valid login on the first try."""
    result = login("target_user", "CorrectPassword123")
    
    assert result.success
    assert result.token is not None
    # Data flow check: Ensure counters remain at 0
    assert USERS["target_user"]["failed_attempts"] == 0


def test_login_wrong_password_increments_counter():
    """Path 3: A single wrong password increments the tracker."""
    result = login("target_user", "WrongPassword")
    
    assert not result.success
    assert result.message == "Invalid credentials"
    # Data flow check: Ensure the attempt was recorded
    assert USERS["target_user"]["failed_attempts"] == 1
    assert USERS["target_user"]["locked_until"] == 0


def test_account_lockout_triggered():
    """Path 4: Hitting the threshold locks the account."""
    # Simulate an attacker firing off rapid failed attempts
    for _ in range(LOCKOUT_THRESHOLD):
        login("target_user", "WrongPassword")
        
    # The next attempt, even if they guess the CORRECT password, should fail
    result = login("target_user", "CorrectPassword123")
    
    assert not result.success
    assert result.message == "Account locked. Try later."
    # Data flow check: Ensure the timestamp was set in the future
    assert USERS["target_user"]["locked_until"] > time.time()


@patch('modules.auth.secure_auth.time.time')
def test_lockout_expiration_sliding_window(mock_time):
    """Path 5: Time travel! The lock expires after the window passes."""
    
    # 1. Freeze time at a specific arbitrary point (e.g., timestamp 1000)
    base_time = 1000.0
    mock_time.return_value = base_time
    
    # 2. Trigger the lockout
    for _ in range(LOCKOUT_THRESHOLD):
        login("target_user", "WrongPassword")
        
    # Verify the user is currently locked
    assert not login("target_user", "CorrectPassword123").success
    
    # 3. Fast-forward time past the LOCKOUT_WINDOW (e.g., 30 seconds + 1)
    mock_time.return_value = base_time + LOCKOUT_WINDOW + 1
    
    # 4. Try logging in again with the correct password
    result = login("target_user", "CorrectPassword123")
    
    # The login should now succeed, and counters should reset
    assert result.success
    assert USERS["target_user"]["failed_attempts"] == 0
    assert USERS["target_user"]["locked_until"] == 0


   

def test_verify_token():
    """Covers decoding a valid JWT."""
    # First, login to generate a real token
    result = login("target_user", "CorrectPassword123")
    token = result.token
    
    # Now verify that token and check the payload
    payload = verify_token(token)
    assert payload["sub"] == "target_user"
    assert "exp" in payload
 

def test_register_duplicate_user():
    """Covers the path where a user tries to register an existing username."""
    # "target_user" is already registered by our setup fixture
    result = register("target_user", "AnotherPassword")
    
    assert not result.success
    assert result.message == "User already exists"    