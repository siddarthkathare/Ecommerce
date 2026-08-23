"""
DEPLOYED APPLICATION (demo)
----------------------------
This is the small e-commerce app referenced in the architecture diagram's
"AUTOMATED DEPLOYMENT / DEPLOYED APPLICATION" boxes: a "secure and reliable
e-commerce application" that the CI/CD pipeline builds, scans, and deploys
via Docker.

It intentionally mirrors the same weaknesses as vulnerable_app.py (SQL
injection, hardcoded secrets, weak hashing, eval, command injection,
insecure deserialization) so the pipeline has something realistic to catch
— but every one of them is fixed here using the secure pattern, to
demonstrate what the pipeline should be pushing every real deployment
towards:

    - Parameterized SQL queries (no string concatenation)
    - Secrets read from environment variables, never hardcoded
    - Passwords hashed with werkzeug's salted PBKDF2, not MD5
    - No eval(), no pickle.loads() on untrusted input
    - No raw shell command construction from user input
"""

import os
import sqlite3

from flask import Flask, g, jsonify, render_template, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "store.db")

# Secure: secrets come from the environment, never hardcoded in source.
app.config["SECRET_KEY"] = os.environ.get("STORE_SECRET_KEY", "dev-only-change-me")

PRODUCTS = [
    {"id": 1, "name": "Wireless Mouse", "price": 19.99},
    {"id": 2, "name": "Mechanical Keyboard", "price": 59.99},
    {"id": 3, "name": "USB-C Hub", "price": 24.50},
    {"id": 4, "name": "27in Monitor", "price": 189.00},
]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    db.commit()
    db.close()


@app.route("/")
def storefront():
    return render_template("store.html", products=PRODUCTS)


@app.route("/api/products")
def api_products():
    return jsonify(PRODUCTS)


@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or len(password) < 8:
        return jsonify({"error": "Username and an 8+ character password are required."}), 400

    # Secure: never store or hash a plain concatenated password; use a
    # salted, slow hash designed for credentials.
    password_hash = generate_password_hash(password)

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "That username is already taken."}), 409

    return jsonify({"success": True})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    db = get_db()
    # Secure: parameterized query — user input is never concatenated into SQL.
    row = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if row is None or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Invalid username or password."}), 401

    return jsonify({"success": True, "message": f"Welcome back, {username}!"})


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5050)
