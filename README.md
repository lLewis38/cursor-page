# cursor-page

Opaque, tamper-evident pagination cursors for Python. Standard library only.

```python
from cursor_page import Cursor, decode_cursor

c = Cursor(key=b"-32-random-bytes-here-----------------", ttl=300)
token = c.encode({"last_id": 42, "sort": "created_at"})
# ... client returns token in the next request ...
position = c.decode(token)   # {"last_id": 42, "sort": "created_at"}
```

## Why

Pagination cursors carry a position from one request to the next. If the
position lives in a query parameter the client can read and edit, a curious
or hostile client can jump to arbitrary offsets, leak counts, or skip access
controls that were enforced on the first page.

This library packs the position into a short, URL-safe token signed with
HMAC-SHA256. The server can recover the position; the client cannot forge one.

The position is **not encrypted**. It is integrity-protected, not confidential.
If the position itself is sensitive, this is the wrong tool. Encryption was
left out on purpose: it would add a dependency or a hand-rolled cipher, and
for pagination the position is rarely secret.

## Edge cases

- **Key rotation is not supported.** If you change the key, every outstanding
cursor becomes invalid. Issue new keys and let old cursors expire.
- **The position travels in the URL**, so keep it small. A couple of fields is
fine; a whole row is not.
- **`ttl` is measured against an injected clock.** Pass `clock=` in tests; the
default is `time.time`.
- **The token is base64, not encrypted.** A client that base64-decodes it can
read the position. They just cannot change it.

## API

- `Cursor(key, ttl=None, clock=time.time)` — constructor. `key` is `bytes` or
  `str`. `ttl` is seconds or `None`. `clock` is a zero-arg callable returning a
  float.
- `Cursor.encode(position)` — returns a `str` token. `position` must be a
  JSON-serialisable `dict`.
- `Cursor.decode(token)` — returns the `dict` position. Raises `CursorError`
  on tamper, malformation, or expiry.
- `decode_cursor(token, key, ttl=None, clock=time.time)` — convenience wrapper
  equivalent to `Cursor(key, ttl, clock).decode(token)`.
- `CursorError` — subclass of `ValueError`.

## Running the tests

```
PYTHONPATH=src python -m unittest discover -s tests
```
