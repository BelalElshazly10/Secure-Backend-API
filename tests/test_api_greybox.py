# tests/test_api_greybox.py
import pytest
import time
from api.app import app
from modules.auth.secure_auth import USERS

# ----------------------------------------------------------
# Setup Fixture
# ----------------------------------------------------------
@pytest.fixture
def client():
    app.config['TESTING'] = True
    
    # Reset internal state before every test
    USERS.clear()
    
    with app.test_client() as client:
        yield client

# ----------------------------------------------------------
# Grey-Box API Tests
# ----------------------------------------------------------

def test_greybox_registration_state(client):
    """Test 1: Does an HTTP registration correctly update the internal dictionary?"""
    # 1. The Black-Box Action: Send the HTTP request
    client.post('/register', json={
        "username": "greybox_user",
        "password": "SecurePassword123"
    })
    
    # 2. The White-Box Check: Peek inside the system memory
    assert "greybox_user" in USERS
    assert USERS["greybox_user"]["password"] != b"SecurePassword123" # Passwords should be hashed!

def test_greybox_lockout_mechanism(client):
    """Test 2: Do failed HTTP logins correctly trigger the internal lockout?"""
    # First, register a target user
    client.post('/register', json={
        "username": "target_user",
        "password": "CorrectPassword"
    })
    
    # 1. The Black-Box Action: Spam 5 failed HTTP login attempts
    for _ in range(5):
        client.post('/login', json={
            "username": "target_user",
            "password": "WrongPassword"
        })
        
    # 2. The White-Box Checks: Look inside the user's specific dictionary!
    # Check that our security engine accurately counted 5 strikes
    assert USERS["target_user"]["failed_attempts"] == 5
    
    # Check that the locked_until timestamp was pushed into the future
    assert USERS["target_user"]["locked_until"] > time.time()
    
    # 3. The Final Verification: Does the API enforce the lock?
    # Sending the CORRECT password should now fail because they are locked out
    response = client.post('/login', json={
        "username": "target_user",
        "password": "CorrectPassword"
    })
    assert response.status_code == 401
    assert "Account locked" in response.get_json()["error"]