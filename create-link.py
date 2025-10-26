# create_link_fixed.py
"""
Creates a token and stores it in the same tokens.db schema used by import_server.py.
Produces a one-time import link to /import?token=...
"""
import secrets
import hashlib
import sqlite3
conn = sqlite3.connect("tokens.db")
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT NOT NULL)")
conn.commit()
conn.close()
from datetime import datetime, timedelta
import os
import argparse

DB_FILE = "tokens.db"
DOMAIN = "http://localhost:5000"   # change for production
TOKEN_TTL_MINUTES = 15

def init_db_if_missing():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL,
            user_id TEXT,
            device_id TEXT,
            expires_at TEXT,
            used INTEGER DEFAULT 0,
            created_at TEXT
        )
        """)
        conn.commit()
        conn.close()

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def create_token_and_store(user_id: str, device_id: str, ttl_minutes: int = TOKEN_TTL_MINUTES):
    token = secrets.token_urlsafe(36)   # URL-safe token
    token_hash = hash_token(token)
    expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    # store in DB
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO tokens (token_hash, user_id, device_id, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (token_hash, user_id, device_id, expires_at.isoformat(), datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return token, expires_at

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--domain", default=DOMAIN)
    parser.add_argument("--ttl", type=int, default=TOKEN_TTL_MINUTES)
    args = parser.parse_args()

    init_db_if_missing()
    token, expires = create_token_and_store(args.user, args.device, args.ttl)
    link = f"{args.domain}/import?token={token}"
    print("ONE-TIME IMPORT LINK (give to consenting device owner):")
    print(link)
    print("Expires (UTC):", expires.isoformat())

if __name__ == "__main__":
    main()
