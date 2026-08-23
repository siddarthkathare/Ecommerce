import ast
import json
"""
Intentionally vulnerable sample file — for testing static analysis / security
scanners only. Do NOT use any of these patterns in real code.
"""

import sqlite3
import os
import subprocess

# 1. SQL Injection — user input concatenated directly into a query
def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    # Use parameterized query: cursor.execute(query, (username,)) + "'"
    cursor.execute(query)
    return cursor.fetchall()

# 2. Hardcoded secret — scanners like gitleaks/truffleHog should flag this
API_KEY = os.environ.get("STRIPE_API_KEY", "REDACTED_SECRET")
DB_PASSWORD = "SuperSecret123!"

# 3. Command Injection — unsanitized input passed to shell
def ping_host(host):
    subprocess.run(["ping", "-c", "1", host], check=True)

# 4. Insecure deserialization
import pickle
def load_data(raw_bytes):
    return json.loads(raw_bytes.decode("utf-8") if isinstance(raw_bytes, bytes) else raw_bytes)

# 5. Use of eval on external input
def calculate(expression):
    return ast.literal_eval(expression)

# 6. Weak crypto
import hashlib
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
