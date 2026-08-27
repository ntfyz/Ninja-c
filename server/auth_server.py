#!/usr/bin/env python3
"""Local Ninja key/HWID service with a SQLite-backed CLI."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
import sqlite3
import sys
import time
from contextlib import closing
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


LOGIN_PATH = "/ninja_ios_v2/api/v1/auth/login"
PBKDF2_ROUNDS = 240_000


SCHEMA = """
CREATE TABLE IF NOT EXISTS license_keys (
    key_name TEXT PRIMARY KEY,
    password_hash BLOB NOT NULL,
    password_salt BLOB NOT NULL,
    hwid TEXT,
    expires_at INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
"""


def connect(database: Path) -> sqlite3.Connection:
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute(SCHEMA)
    return connection


def password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)


def generate_key() -> str:
    raw = secrets.token_hex(12).upper()
    return "NINJA-" + "-".join(raw[index : index + 6] for index in range(0, len(raw), 6))


def create_key(database: Path, key_name: str, password: str, days: int) -> None:
    now = int(time.time())
    expires_at = now + days * 86400
    salt = secrets.token_bytes(16)
    digest = password_digest(password, salt)
    with closing(connect(database)) as connection:
        connection.execute(
            """
            INSERT INTO license_keys
                (key_name, password_hash, password_salt, hwid, expires_at, enabled,
                 created_at, updated_at)
            VALUES (?, ?, ?, NULL, ?, 1, ?, ?)
            ON CONFLICT(key_name) DO UPDATE SET
                password_hash=excluded.password_hash,
                password_salt=excluded.password_salt,
                expires_at=excluded.expires_at,
                enabled=1,
                updated_at=excluded.updated_at
            """,
            (key_name, digest, salt, expires_at, now, now),
        )
        connection.commit()
    print(json.dumps({"key": key_name, "password": password, "expires_at": expires_at}))


def delete_key(database: Path, key_name: str) -> None:
    with closing(connect(database)) as connection:
        cursor = connection.execute("DELETE FROM license_keys WHERE key_name=?", (key_name,))
        connection.commit()
    print(json.dumps({"deleted": cursor.rowcount == 1, "key": key_name}))


def set_hwid(database: Path, key_name: str, hwid: str | None) -> None:
    if hwid is not None and (len(hwid) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in hwid)):
        raise SystemExit("HWID must contain exactly 64 hexadecimal characters")
    now = int(time.time())
    with closing(connect(database)) as connection:
        cursor = connection.execute(
            "UPDATE license_keys SET hwid=?, updated_at=? WHERE key_name=?",
            (hwid.lower() if hwid else None, now, key_name),
        )
        connection.commit()
    print(json.dumps({"updated": cursor.rowcount == 1, "key": key_name, "hwid": hwid}))


def set_enabled(database: Path, key_name: str, enabled: bool) -> None:
    now = int(time.time())
    with closing(connect(database)) as connection:
        cursor = connection.execute(
            "UPDATE license_keys SET enabled=?, updated_at=? WHERE key_name=?",
            (int(enabled), now, key_name),
        )
        connection.commit()
    print(json.dumps({"updated": cursor.rowcount == 1, "key": key_name, "enabled": enabled}))


def list_keys(database: Path) -> None:
    with closing(connect(database)) as connection:
        rows = connection.execute(
            "SELECT key_name, hwid, expires_at, enabled, created_at, updated_at "
            "FROM license_keys ORDER BY created_at DESC"
        ).fetchall()
    print(json.dumps([dict(row) for row in rows], indent=2))


@dataclass
class LoginResult:
    status: HTTPStatus
    payload: dict[str, Any]


def authenticate(database: Path, username: str, password: str, device_id: str) -> LoginResult:
    if not username or not password:
        return LoginResult(HTTPStatus.BAD_REQUEST, {"ok": False, "code": "malformed_credentials"})
    if len(device_id) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in device_id):
        return LoginResult(HTTPStatus.BAD_REQUEST, {"ok": False, "code": "device_id_unavailable"})

    now = int(time.time())
    normalized_hwid = device_id.lower()
    with closing(connect(database)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM license_keys WHERE key_name=?", (username,)
        ).fetchone()
        if row is None or not hmac.compare_digest(
            bytes(row["password_hash"]), password_digest(password, bytes(row["password_salt"]))
        ):
            connection.rollback()
            return LoginResult(HTTPStatus.UNAUTHORIZED, {"ok": False, "code": "invalid_credentials"})
        if not row["enabled"]:
            connection.rollback()
            return LoginResult(HTTPStatus.FORBIDDEN, {"ok": False, "code": "key_disabled"})
        if row["expires_at"] <= now:
            connection.rollback()
            return LoginResult(HTTPStatus.FORBIDDEN, {"ok": False, "code": "key_expired"})
        if row["hwid"] and row["hwid"] != normalized_hwid:
            connection.rollback()
            return LoginResult(HTTPStatus.FORBIDDEN, {"ok": False, "code": "device_mismatch"})
        if not row["hwid"]:
            connection.execute(
                "UPDATE license_keys SET hwid=?, updated_at=? WHERE key_name=?",
                (normalized_hwid, now, username),
            )
        connection.commit()

    generation = secrets.randbits(63) or 1
    remaining = int(row["expires_at"]) - now
    return LoginResult(
        HTTPStatus.OK,
        {
            "ok": True,
            "scope": "authenticated",
            "expires_at": int(row["expires_at"]),
            "remaining_seconds": remaining,
            "generation": generation,
            "device_id": normalized_hwid,
        },
    )


def make_handler(database: Path) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "NinjaLocalAuth/1.0"

        def send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(status.value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self.send_json(HTTPStatus.OK, {"ok": True})
            else:
                self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "code": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != LOGIN_PATH:
                self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "code": "not_found"})
                return
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
                if content_length <= 0 or content_length > 16_384:
                    raise ValueError("invalid body length")
                payload = json.loads(self.rfile.read(content_length))
                result = authenticate(
                    database,
                    str(payload.get("username", "")),
                    str(payload.get("password", "")),
                    str(payload.get("device_id", "")),
                )
                self.send_json(result.status, result.payload)
            except (ValueError, TypeError, json.JSONDecodeError):
                self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "code": "malformed_request"})

        def log_message(self, message: str, *args: object) -> None:
            sys.stderr.write("%s - %s\n" % (self.address_string(), message % args))

    return Handler


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path("ninja-auth.sqlite3"))
    subcommands = parser.add_subparsers(dest="command", required=True)

    serve = subcommands.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8880)

    create = subcommands.add_parser("create-key")
    create.add_argument("--key", default=None)
    create.add_argument("--password", default=None)
    create.add_argument("--days", type=int, default=30)

    delete = subcommands.add_parser("delete-key")
    delete.add_argument("key")

    update_hwid = subcommands.add_parser("set-hwid")
    update_hwid.add_argument("key")
    update_hwid.add_argument("hwid")

    clear_hwid = subcommands.add_parser("clear-hwid")
    clear_hwid.add_argument("key")

    enable = subcommands.add_parser("enable-key")
    enable.add_argument("key")

    disable = subcommands.add_parser("disable-key")
    disable.add_argument("key")

    subcommands.add_parser("list-keys")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    database = args.db.resolve()
    if args.command == "serve":
        server = ThreadingHTTPServer((args.host, args.port), make_handler(database))
        print(f"Serving {LOGIN_PATH} on http://{args.host}:{args.port} using {database}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    elif args.command == "create-key":
        key_name = args.key or generate_key()
        password = args.password or key_name
        create_key(database, key_name, password, args.days)
    elif args.command == "delete-key":
        delete_key(database, args.key)
    elif args.command == "set-hwid":
        set_hwid(database, args.key, args.hwid)
    elif args.command == "clear-hwid":
        set_hwid(database, args.key, None)
    elif args.command == "enable-key":
        set_enabled(database, args.key, True)
    elif args.command == "disable-key":
        set_enabled(database, args.key, False)
    elif args.command == "list-keys":
        list_keys(database)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
