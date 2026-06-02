from modules.auth import secure_auth

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlciIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzY1NTgxNDA0LCJleHAiOjE3NjU1ODIzMDR9.bDSkoKQw8RPygkUbSv3LIehzFG6sxNm8ferTNwlV68Y"

# Decode and verify the token
try:
    decoded = secure_auth.verify_token(token)
    print("Decoded token:", decoded)
except Exception as e:
    print("Error verifying token:", e)
