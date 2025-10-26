# import_server.py
import os
import sqlite3
import hashlib
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory, g
from werkzeug.utils import secure_filename

# === CONFIG ===
DB_FILE = "tokens.db"
UPLOAD_ROOT = "uploads"
LOG_FILE = "import_server.log"
MAX_FILE_SIZE_BYTES = 200 * 1024 * 1024  # 200 MB per file
ALLOWED_MIME_PREFIXES = ("image/", "video/")
TOKEN_TTL_MINUTES = 15

# === Logging ===
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

app = Flask(__name__)
os.makedirs(UPLOAD_ROOT, exist_ok=True)

# === DB helpers ===
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = sqlite3.connect(DB_FILE, detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
        g._database = db
    return db

def close_db(e=None):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

app.teardown_appcontext(close_db)

def init_db():
    log.info("Initializing DB (if not exists)...")
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_hash TEXT NOT NULL UNIQUE,
        user_id TEXT,
        device_id TEXT,
        expires_at TEXT,
        used INTEGER DEFAULT 0,
        created_at TEXT
    )
    """)
    conn.commit()
    conn.close()
    log.info("DB ready.")

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def store_token(token_hash: str, user_id: str, device_id: str, expires_at: datetime):
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        INSERT INTO tokens (token_hash, user_id, device_id, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (token_hash, user_id, device_id, expires_at.isoformat(), datetime.utcnow().isoformat()))
    db.commit()

def find_token_record(token: str):
    token_hash = hash_token(token)
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM tokens WHERE token_hash = ?", (token_hash,))
    row = cur.fetchone()
    return row

def mark_token_used(token: str):
    token_hash = hash_token(token)
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE tokens SET used = 1 WHERE token_hash = ?", (token_hash,))
    db.commit()

# === Utilities ===
def ensure_upload_path(user_id, device_id):
    safe_user = secure_filename(str(user_id) or "unknown_user")
    safe_device = secure_filename(str(device_id) or "unknown_device")
    path = os.path.join(UPLOAD_ROOT, safe_user, safe_device)
    os.makedirs(path, exist_ok=True)
    return path

# === Routes ===
@app.route("/import", methods=["GET", "POST"])
def import_page():
    try:
        if request.method == "GET":
            token = request.args.get("token", "")
            if not token:
                return "Missing token", 400
            row = find_token_record(token)
            if not row:
                return "Invalid token", 400
            if row["used"]:
                return "This link has already been used.", 400
            expires_at = datetime.fromisoformat(row["expires_at"])
            if datetime.utcnow() > expires_at:
                return "Token expired", 400

            # Minimal HTML form when open in browser
            return f"""
            <!doctype html>
            <html>
            <head><meta charset="utf-8"><title>Upload files</title></head>
            <body>
              <h3>Upload photos & videos (consent required)</h3>
              <p>User ID: {row['user_id']}, Device ID: {row['device_id']}</p>
              <form method="post" enctype="multipart/form-data">
                <input type="hidden" name="token" value="{token}">
                <input type="file" name="files" accept="image/*,video/*" multiple required>
                <br/><br/>
                <button type="submit">Upload</button>
              </form>
            </body>
            </html>
            """

        # POST - handle upload
        token = request.form.get("token") or request.args.get("token")
        if not token:
            return jsonify({"error": "Missing token"}), 400

        row = find_token_record(token)
        if not row:
            return jsonify({"error": "Invalid token"}), 400
        if row["used"]:
            return jsonify({"error": "Token already used"}), 400

        expires_at = datetime.fromisoformat(row["expires_at"])
        if datetime.utcnow() > expires_at:
            return jsonify({"error": "Token expired"}), 400

        if "files" not in request.files:
            return jsonify({"error": "No files part in request"}), 400

        files = request.files.getlist("files")
        if not files:
            return jsonify({"error": "No files uploaded"}), 400

        upload_path = ensure_upload_path(row["user_id"], row["device_id"])
        saved = []
        for f in files:
            # content type check
            ct = f.content_type or ""
            if not any(ct.startswith(pref) for pref in ALLOWED_MIME_PREFIXES):
                log.warning("Rejected file due to mime: %s %s", f.filename, ct)
                return jsonify({"error": f"Disallowed file type: {ct}"}), 400

            # file size check: read stream length safely
            f.stream.seek(0, os.SEEK_END)
            size = f.stream.tell()
            f.stream.seek(0)
            if size > MAX_FILE_SIZE_BYTES:
                return jsonify({"error": f"File too large: {f.filename} ({size} bytes)"}), 400

            safe_name = secure_filename(f.filename) or f"upload_{int(datetime.utcnow().timestamp())}"
            dest = os.path.join(upload_path, f"{int(datetime.utcnow().timestamp())}_{safe_name}")
            try:
                f.save(dest)
            except Exception as e:
                log.exception("Failed to save file %s: %s", f.filename, e)
                return jsonify({"error": f"Failed to save file {f.filename}"}), 500
            saved.append(os.path.relpath(dest))

        # mark token used only after all files saved successfully
        mark_token_used(token)
        log.info("Upload success: %s files saved for token ending %s", len(saved), token[-6:])
        return jsonify({"ok": True, "saved": saved}), 200

    except Exception as ex:
        log.exception("Unhandled exception in /import")
        return jsonify({"error": "Internal server error", "detail": str(ex)}), 500

@app.route("/uploads/<path:filepath>", methods=["GET"])
def serve_upload(filepath):
    # development-only file fetcher
    base = os.path.abspath(UPLOAD_ROOT)
    return send_from_directory(base, filepath)

# === CLI helpers for testing ===
def create_test_token(user_id="test_user", device_id="test_device", ttl_minutes=TOKEN_TTL_MINUTES):
    token = os.urandom(24).hex()  # token for the test; not urlsafe but ok for testing
    token_hash = hash_token(token)
    expires = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    # store using a direct connection (bypass get_db)
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO tokens (token_hash, user_id, device_id, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (token_hash, user_id, device_id, expires.isoformat(), datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return token, expires

if __name__ == "__main__":
    # init DB automatically on start
    init_db()
    import argparse
    parser = argparse.ArgumentParser(description="Import server")
    parser.add_argument("--create-token", action="store_true", help="Create a quick test token and print it")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    if args.create_token:
        token, exp = create_test_token()
        print("TEST TOKEN:", token)
        print("Use URL: http://localhost:{p}/import?token={t}".format(p=args.port, t=token))
        print("Expires at (UTC):", exp.isoformat())
    else:
        log.info("Starting import server on %s:%s", args.host, args.port)
        app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
