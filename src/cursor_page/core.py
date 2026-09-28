"""Opaque, tamper-evident pagination cursors.

A cursor is a short string the server hands to the client so the client can
ask for the next page. The server needs to recover the position from that
string, but it must not let clients forge or read arbitrary positions.

This module packs a position payload and a MAC into a URL-safe token. The
position is not encrypted; it is only integrity-protected. That is a
deliberate trade-off: encryption would hide the position from the client,
but for pagination the position is not secret, and skipping the cipher keeps
the implementation small and the token short.

The MAC is HMAC-SHA256 with a server-held key. A client that tampers with the
position cannot produce a matching tag, so the server rejects the cursor.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.parse


class CursorError(ValueError):
    """Raised when a cursor is malformed, tampered with, or expired."""


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    pad = (-len(text)) % 4
    return base64.urlsafe_b64decode(text + ("=" * pad))


def _sign(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


class Cursor:
    """Build and verify tamper-evident pagination cursors.

    Parameters
    ----------
    key:
        Secret key shared by every process that issues or verifies cursors.
        Any bytes-like value works; pass at least 32 random bytes in
        production. If a key is compromised, all outstanding cursors are
        forgeable.
    ttl:
        Maximum age in seconds before a cursor is rejected. ``None`` disables
        expiry. Expiry is measured against the ``clock`` callable so tests can
        pass a deterministic fake.
    clock:
        Zero-argument callable returning the current time as a float, in
        seconds since the Unix epoch. Defaults to ``time.time``. Inject a fake
        in tests; never assert on wall-clock time.
    """

    def __init__(self, key, ttl=None, clock=time.time):
        if isinstance(key, str):
            key = key.encode("utf-8")
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes or str")
        if len(key) < 1:
            raise ValueError("key must be non-empty")
        self._key = bytes(key)
        self.ttl = ttl
        self._clock = clock

    def encode(self, position):
        """Return an opaque cursor string for *position*.

        *position* must be JSON-serialisable. It is the caller's responsibility
        to keep it small; cursors travel in URLs.
        """
        if not isinstance(position, dict):
            raise TypeError("position must be a dict")
        try:
            body = json.dumps(position, separators=(",", ":"), sort_keys=True)
        except TypeError as exc:
            raise TypeError("position must be JSON-serialisable: " + str(exc))
        issued = int(self._clock())
        payload = {"p": position, "t": issued}
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        tag = _sign(self._key, raw)
        token = _b64encode(raw) + "." + _b64encode(tag)
        return token

    def decode(self, token):
        """Verify *token* and return the stored position.

        Raises :class:`CursorError` if the token is malformed, the tag does
        not match, or the token has expired.
        """
        if not isinstance(token, str):
            raise CursorError("token must be a string")
        if "." not in token:
            raise CursorError("missing tag separator")
        body_b64, tag_b64 = token.rsplit(".", 1)
        try:
            raw = _b64decode(body_b64)
            tag = _b64decode(tag_b64)
        except Exception:
            raise CursorError("invalid base64")
        expected = _sign(self._key, raw)
        if not hmac.compare_digest(tag, expected):
            raise CursorError("signature mismatch")
        try:
            payload = json.loads(raw)
        except ValueError:
            raise CursorError("invalid payload json")
        if not isinstance(payload, dict) or "p" not in payload or "t" not in payload:
            raise CursorError("malformed payload")
        issued = payload["t"]
        if not isinstance(issued, int) or isinstance(issued, bool):
            raise CursorError("malformed timestamp")
        if self.ttl is not None:
            now = self._clock()
            if issued > now + 0.0:
                raise CursorError("issued in the future")
            if now - issued > self.ttl:
                raise CursorError("expired")
        return payload["p"]


def decode_cursor(token, key, ttl=None, clock=time.time):
    """Convenience wrapper: verify *token* with *key* and return the position.

    Equivalent to ``Cursor(key, ttl, clock).decode(token)``.
    """
    return Cursor(key, ttl=ttl, clock=clock).decode(token)
