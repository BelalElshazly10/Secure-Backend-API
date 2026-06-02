# tests/test_api_blackbox.py
import pytest
from api.app import app

# ----------------------------------------------------------
# Setup Fixture: The Invisible Browser
# ----------------------------------------------------------
@pytest.fixture
def client():
    """Sets up a Flask test client (our invisible Postman)"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

# ----------------------------------------------------------
# Black-Box API Tests
# ----------------------------------------------------------

def test_api_register_user(client):
    """Test 1: Can a user register via the API?"""
    # Send a POST request to /register
    response = client.post('/register', json={
        "username": "blackbox_tester",
        "password": "SuperSecretPassword1!"
    })
    
    # Black-box check: We only care about the HTTP status code!
    # It should be 201 (Created) or 400 (if we run the test twice and they exist)
    assert response.status_code in [201, 400]

def test_api_login_success(client):
    """Test 2: Can the user log in and get a token?"""
    # Send a POST request to /login
    response = client.post('/login', json={
        "username": "blackbox_tester",
        "password": "SuperSecretPassword1!"
    })
    
    # Black-box check: Did we get a 200 OK?
    assert response.status_code == 200
    
    # Black-box check: Is there a token in the JSON response?
    data = response.get_json()
    assert "token" in data

def test_api_login_failure(client):
    """Test 3: Does the API reject bad passwords?"""
    response = client.post('/login', json={
        "username": "blackbox_tester",
        "password": "WrongPassword!"
    })
    
    # Black-box check: We expect a 401 Unauthorized status
    assert response.status_code == 401
    
    # Black-box check: We expect an error message in the JSON
    data = response.get_json()
    assert "error" in data

def test_api_encryption_flow(client):
    """Test 4: Does the encrypt endpoint return a cipher?"""
    response = client.post('/encrypt', json={
        "text": "Hello World"
    })
    
    assert response.status_code == 200
    data = response.get_json()
    assert "cipher" in data