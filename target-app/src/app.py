import os
import sqlite3
import hashlib
import logging
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("DB_PATH", "/tmp/app.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_reports (
            id INTEGER PRIMARY KEY,
            commit_sha TEXT NOT NULL,
            branch TEXT,
            risk_score INTEGER,
            gate_passed BOOLEAN,
            findings_json TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")
        expected = os.environ.get("API_KEY")
        if not expected or api_key != expected:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def hash_password(password: str) -> str:
    salt = os.environ.get("PASSWORD_SALT", "default-salt-change-me")
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})


@app.route("/api/users", methods=["POST"])
@require_auth
def create_user():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "username and password required"}), 400

    username = data["username"]
    password_hash = hash_password(data["password"])
    role = data.get("role", "user")

    if role not in ("user", "viewer"):
        return jsonify({"error": "invalid role"}), 400

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role),
        )
        conn.commit()
        logger.info("Created user: %s", username)
        return jsonify({"message": "user created", "username": username}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already exists"}), 409
    finally:
        conn.close()


@app.route("/api/users/<username>", methods=["GET"])
@require_auth
def get_user(username: str):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, username, role, created_at FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row:
            return jsonify({"error": "user not found"}), 404
        return jsonify(dict(row))
    finally:
        conn.close()


@app.route("/api/reports", methods=["POST"])
@require_auth
def ingest_report():
    import json
    data = request.get_json()
    required = ("commit_sha", "risk_score", "gate_passed", "findings")
    for field in required:
        if field not in data:
            return jsonify({"error": f"missing field: {field}"}), 400

    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO scan_reports
               (commit_sha, branch, risk_score, gate_passed, findings_json)
               VALUES (?, ?, ?, ?, ?)""",
            (
                data["commit_sha"],
                data.get("branch", "unknown"),
                int(data["risk_score"]),
                bool(data["gate_passed"]),
                json.dumps(data["findings"]),
            ),
        )
        conn.commit()
        return jsonify({"message": "report ingested", "id": conn.lastrowid}), 201
    finally:
        conn.close()


@app.route("/api/reports", methods=["GET"])
@require_auth
def list_reports():
    import json
    limit = min(int(request.args.get("limit", 50)), 200)
    conn = get_db()
    try:
        rows = conn.execute(
            """SELECT id, commit_sha, branch, risk_score, gate_passed, scanned_at
               FROM scan_reports ORDER BY scanned_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
