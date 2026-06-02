# Secure Authentication & Cryptography API (AQA System)

A robust, security-first REST API built with Python and Flask, serving as the backend for an Automated Quality Assurance (AQA) System. This project demonstrates defense-in-depth engineering principles, featuring stateless JWT authentication, cryptographic data protection, and active mitigations against brute-force and timing attacks.

Developed as a 4th-Year Software Engineering Project.

## 🛡️ Core Security Features

* **Stateless Authentication:** Secure session management using JSON Web Tokens (JWT) signed with HMAC-SHA256 (HS256) utilizing a cryptographically secure 32+ byte secret key.
* **Brute-Force Mitigation:** Implements a sliding-window account lockout mechanism. After 5 failed consecutive attempts, accounts are locked for a configurable time window (default 30 seconds).
* **Timing Attack Prevention:** Deliberate execution delays (`time.sleep`) mask the time difference between verifying existing users and rejecting non-existent users, preventing user enumeration.
* **Secure Password Storage:** Automated salting and hashing utilizing `bcrypt`.
* **Data Cryptography:** Provides endpoints for AES symmetric encryption and decryption using `pycryptodome`.
* **HTTP Security:** Global middleware intercepts all outgoing responses to inject strict security headers, including:
  * `Content-Security-Policy` (CSP)
  * `Strict-Transport-Security` (HSTS)
  * `X-Frame-Options` (Clickjacking defense)
  * `X-Content-Type-Options` (MIME-sniffing defense)

## 💻 Tech Stack

* **Framework:** Python 3 / Flask
* **Security & Crypto:** PyJWT, bcrypt, pycryptodome, cryptography
* **Testing:** pytest, pytest-cov

## 🚀 Getting Started

### 1. Installation
Clone the repository and install the required dependencies:
```bash
# Create and activate a virtual environment (Recommended)
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
