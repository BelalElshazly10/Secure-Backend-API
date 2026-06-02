# api/app.py
import sys
import os
from google import genai
from google.genai import types
from dotenv import load_dotenv
# 1. Force Python to look in the exact right folder
basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
load_dotenv(os.path.join(basedir, '.env'))

# 2. Grab the key manually
API_KEY = os.getenv("GEMINI_API_KEY")

# 3. A safety check if Windows hid the file extension!
if not API_KEY:
    print("\n🚨 WARNING: Python could not find your .env file!")
    print("🚨 Let's bypass the file for a moment so you can test the app.\n")
    
    # TEMPORARY BYPASS: Paste your actual AIzaSy... key right here between the quotes
    # (Just don't upload this file to GitHub while your key is pasted here!)
    API_KEY = "YOUR_ACTUAL_KEY_HERE"

# 4. Initialize Gemini using the explicit key
gemini_client = genai.Client(api_key=API_KEY)

# Add the parent directory to Python's import path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps

# Import modules
#from modules.auth import secure_auth
from modules.auth.secure_auth import register, login, verify_token
from modules.validation.validation import validate_username, validate_email, validate_text
from modules.encryption.aes import encrypt, decrypt
from modules.logging.logger import log_info, log_security_event

app = Flask(__name__)
CORS(app)

# ----------------------------------------------------------
# Security Headers
# ----------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ----------------------------------------------------------
# JWT Protection Decorator
# ----------------------------------------------------------
def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # 1. Let the CORS scout through
        if request.method == "OPTIONS":
            return jsonify({}), 200

        # 2. Grab the header
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return jsonify({"error": "Missing token"}), 401

        # 3. Strip the word "Bearer " to get JUST the raw token string
        try:
            token = auth_header.split(" ")[1]
        except IndexError:
            # If they sent a token without "Bearer ", just use the raw header
            token = auth_header

        # 4. Verify the token
        try:
            payload = verify_token(token)
        except Exception as e:
            print(f"Token verification failed: {e}") # This will print the exact reason to your terminal!
            return jsonify({"error": "Invalid or expired token"}), 401

        return f(payload, *args, **kwargs)

    return wrapper


# ----------------------------------------------------------
# Register
# ----------------------------------------------------------
@app.route("/register", methods=["POST"])
def api_register():
    data = request.json

    username = data.get("username")
    password = data.get("password")

    if not validate_username(username):
        return jsonify({"error": "Invalid username"}), 400

    result = register(username, password)

    if result.success:
        log_info(f"User {username} registered.")
        return jsonify({"message": result.message}), 201

    return jsonify({"error": result.message}), 400

@app.route("/", methods=["GET"])
def index():
    return {"status": "API is running"}

# ----------------------------------------------------------
# Login
# ----------------------------------------------------------
@app.route("/login", methods=["POST"])
def api_login():
    data = request.json

    username = data.get("username")
    password = data.get("password")

    result = login(username, password)

    if result.success:
        log_security_event(f"User {username} logged in.")
        return jsonify({"token": result.token})

    log_security_event(f"Failed login attempt for {username}.")
    return jsonify({"error": result.message}), 401


# ----------------------------------------------------------
# Input Validation
# ----------------------------------------------------------
@app.route("/validate", methods=["POST"])
def api_validate():
    data = request.json

    text = data.get("text")

    if validate_text(text):
        return jsonify({"valid": True})
    else:
        return jsonify({"valid": False}), 400


# ----------------------------------------------------------
# Encrypt
# ----------------------------------------------------------
@app.route("/encrypt", methods=["POST"])
def api_encrypt():
    data = request.json
    text = data.get("text")

    cipher = encrypt(text)

    log_info("AES encryption performed.")

    return jsonify({"cipher": cipher})


# ----------------------------------------------------------
# Decrypt
# ----------------------------------------------------------
@app.route("/decrypt", methods=["POST"])
def api_decrypt():
    data = request.json
    cipher = data.get("cipher")

    try:
        plain = decrypt(cipher)
        return jsonify({"plain": plain})
    except Exception:
        return jsonify({"error": "Decryption failed"}), 400


# ----------------------------------------------------------
# Secure endpoint (JWT required)
# ----------------------------------------------------------
@app.route("/secure-data", methods=["GET"])
@token_required
def secure_data(payload):
    username = payload["sub"]

    log_info(f"Secure data accessed by {username}")

    return jsonify({
        "message": f"Hello {username}, this is protected data.",
        "role": payload["role"]
    })



#@app.route("/api/verify_token", methods=["POST"])
#def api_verify_token():
 #   data = request.json
  #  token = data.get("token")
   # if not token:
    #    return jsonify({"valid": False, "message": "Token missing"}), 400
#
 #   try:
  #      payload = secure_auth.verify_token(token)
   #     return jsonify({"valid": True, "payload": payload})
    #except Exception as e:
     #   return jsonify({"valid": False, "message": str(e)}), 401

@app.route("/analyze", methods=["POST", "OPTIONS"])
@token_required
def analyze_requirement(payload): # The payload comes from the token_required decorator
    # Get the requirement text sent from the React frontend
    data = request.get_json()
    requirement_text = data.get("requirement")

    if not requirement_text:
        return jsonify({"error": "No requirement text provided"}), 400

    prompt = f"""Analyze the following software requirement and generate a comprehensive QA assessment:
    
Requirement: "{requirement_text}"

Tasks:
1. Identify the requirement type.
2. Interpret the requirement and list its strengths and weaknesses.
3. Generate structured ISTQB-compliant test cases using Equivalence Partitioning (EP), Boundary Value Analysis (BVA), and Decision Table Testing (DTT) where applicable.
4. Evaluate quality using McCall's Quality Model (scores 0-1.0 for each factor).
5. Perform a Proposal/Contract review checklist assessment.
6. Provide an overall coverage score (0-100) and confidence score (0-1.0).

Return the response as a JSON object matching the defined schema."""

    # Define the strict JSON structure we want Gemini to return
    analysis_schema = {
        "type": "OBJECT",
        "properties": {
            "type": {"type": "STRING"},
            "coverageScore": {"type": "NUMBER"},
            "interpretation": {"type": "STRING"},
            "strengths": {"type": "ARRAY", "items": {"type": "STRING"}},
            "weaknesses": {"type": "ARRAY", "items": {"type": "STRING"}},
            "testCases": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "id": {"type": "STRING"},
                        "title": {"type": "STRING"},
                        "preconditions": {"type": "STRING"},
                        "steps": {"type": "ARRAY", "items": {"type": "STRING"}},
                        "testData": {"type": "STRING"},
                        "expectedResult": {"type": "STRING"},
                        "techniqueUsed": {"type": "STRING"}
                    },
                    "required": ["id", "title", "steps", "expectedResult", "techniqueUsed"]
                }
            },
            "mccallFactors": {
                "type": "OBJECT",
                "properties": {
                    "correctness": {"type": "NUMBER"},
                    "reliability": {"type": "NUMBER"},
                    "efficiency": {"type": "NUMBER"},
                    "integrity": {"type": "NUMBER"},
                    "usability": {"type": "NUMBER"},
                    "maintainability": {"type": "NUMBER"},
                    "flexibility": {"type": "NUMBER"},
                    "testability": {"type": "NUMBER"},
                    "portability": {"type": "NUMBER"},
                    "reusability": {"type": "NUMBER"},
                    "interoperability": {"type": "NUMBER"}
                }
            },
            "reviewChecklist": {
                "type": "OBJECT",
                "properties": {
                    "customerRequirementsClarified": {"type": "BOOLEAN"},
                    "alternativeSolutionsEvaluated": {"type": "BOOLEAN"},
                    "risksIdentified": {"type": "BOOLEAN"},
                    "resourcesEstimated": {"type": "BOOLEAN"},
                    "capacityConfirmed": {"type": "BOOLEAN"},
                    "customerObligationsVerified": {"type": "BOOLEAN"},
                    "partnerParticipationDefined": {"type": "BOOLEAN"},
                    "proprietaryRightsProtected": {"type": "BOOLEAN"},
                    "noUnresolvedIssues": {"type": "BOOLEAN"},
                    "allUnderstandingsDocumented": {"type": "BOOLEAN"},
                    "noUndocumentedChanges": {"type": "BOOLEAN"}
                }
            },
            "techniquesUsed": {"type": "ARRAY", "items": {"type": "STRING"}},
            "confidenceScore": {"type": "NUMBER"}
        },
        "required": ["type", "coverageScore", "interpretation", "testCases", "mccallFactors", "techniquesUsed", "confidenceScore"]
    }

    try:
        # Call the Gemini API from the secure backend
        response = gemini_client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=analysis_schema,
            ),
        )
        
        # Send the JSON string right back to React
        return response.text, 200, {'Content-Type': 'application/json'}

    except Exception as e:
        print(f"Gemini API Error: {e}")
        return jsonify({"error": "Failed to analyze requirement"}), 500


@app.route("/api/verify_token", methods=["POST"])
def api_verify_token():
    data = request.json
    token = data.get("token")
    if not token:
        return jsonify({"valid": False, "message": "Token missing"}), 400

    try:
        # Changed this line to remove the 'secure_auth.' prefix
        payload = verify_token(token)
        return jsonify({"valid": True, "payload": payload})
    except Exception as e:
        return jsonify({"valid": False, "message": str(e)}), 401


# ----------------------------------------------------------
# Run server
# ----------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
