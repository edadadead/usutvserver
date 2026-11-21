import os
import secrets
import sqlite3
import time
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
CORS(app)

DB_PATH = os.environ.get("DB_PATH", "usutv_users.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                token TEXT,
                created_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS command_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                value TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )


init_db()


def get_user_by_token(token: str):
    if not token:
        return None
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE token = ?", (token,)).fetchone()


@app.route("/", methods=["GET"])
def index():
    return jsonify({"service": "USUTV Account & Relay Server", "status": "online"})


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    if len(username) < 3 or len(password) < 4:
        return jsonify({"status": "error", "message": "Username (3+ chars) and password (4+ chars) required."}), 400

    pw_hash = generate_password_hash(password)
    token = secrets.token_hex(24)

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, token, created_at) VALUES (?, ?, ?, ?)",
                (username, pw_hash, token, time.time()),
            )
        return jsonify({"status": "ok", "username": username, "token": token})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Username already exists."}), 409


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            return jsonify({"status": "error", "message": "Invalid username or password."}), 401

        token = user["token"] or secrets.token_hex(24)
        conn.execute("UPDATE users SET token = ? WHERE id = ?", (token, user["id"]))

    return jsonify({"status": "ok", "username": user["username"], "token": token})


@app.route("/api/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    user = get_user_by_token((data.get("token") or "").strip())
    if not user:
        return jsonify({"status": "error", "message": "Session expired or invalid."}), 401
    return jsonify({"status": "ok", "username": user["username"]})


@app.route("/api/command", methods=["POST"])
def push_command():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    user = get_user_by_token(token)
    if not user:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    action = (data.get("action") or "").strip()
    value = str(data.get("value") or "")
    if not action:
        return jsonify({"status": "error", "message": "Missing action"}), 400

    with get_db() as conn:
        conn.execute(
            "INSERT INTO command_queue (user_id, action, value, created_at) VALUES (?, ?, ?, ?)",
            (user["id"], action, value, time.time()),
        )
    return jsonify({"status": "ok"})


@app.route("/api/poll", methods=["GET"])
def poll_commands():
    token = (request.args.get("token") or "").strip()
    user = get_user_by_token(token)
    if not user:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, action, value FROM command_queue WHERE user_id = ? ORDER BY id ASC LIMIT 20",
            (user["id"],),
        ).fetchall()
        if rows:
            ids = [r["id"] for r in rows]
            placeholders = ",".join("?" for _ in ids)
            conn.execute(f"DELETE FROM command_queue WHERE id IN ({placeholders})", ids)

    commands = [{"action": r["action"], "value": r["value"]} for r in rows]
    return jsonify({"status": "ok", "commands": commands})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
