import json
import unittest

from cursor_page import Cursor, CursorError, decode_cursor


class FakeClock:
    def __init__(self, start=0.0):
        self.now = float(start)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class TestEncodeDecode(unittest.TestCase):
    def test_roundtrip(self):
        c = Cursor(b"k" * 32)
        token = c.encode({"id": 42, "dir": "next"})
        self.assertEqual(c.decode(token), {"id": 42, "dir": "next"})

    def test_token_is_url_safe_string(self):
        c = Cursor(b"k" * 32)
        token = c.encode({"id": 1})
        self.assertIsInstance(token, str)
        # No characters that need URL-encoding.
        self.assertEqual(token, urllib_quote_safe(token))

    def test_str_key_accepted(self):
        c = Cursor("secret-key-please-use-32-bytes!!")
        token = c.encode({"id": 1})
        self.assertEqual(c.decode(token), {"id": 1})

    def test_empty_key_rejected(self):
        with self.assertRaises(ValueError):
            Cursor(b"")

    def test_non_dict_position_rejected(self):
        c = Cursor(b"k" * 32)
        with self.assertRaises(TypeError):
            c.encode([1, 2, 3])

    def test_non_json_position_rejected(self):
        c = Cursor(b"k" * 32)
        with self.assertRaises(TypeError):
            c.encode({"bad": object()})


class TestTamperEvidence(unittest.TestCase):
    def test_wrong_key_rejects(self):
        a = Cursor(b"key-a" + b"0" * 26)
        b = Cursor(b"key-b" + b"0" * 26)
        token = a.encode({"id": 1})
        with self.assertRaises(CursorError):
            b.decode(token)

    def test_modified_body_rejected(self):
        c = Cursor(b"k" * 32)
        token = c.encode({"id": 1})
        body, tag = token.rsplit(".", 1)
        # Flip a character in the body. Keep it base64-valid.
        swapped = body[:-1] + ("A" if body[-1] != "A" else "B")
        with self.assertRaises(CursorError):
            c.decode(swapped + "." + tag)

    def test_modified_tag_rejected(self):
        c = Cursor(b"k" * 32)
        token = c.encode({"id": 1})
        body, tag = token.rsplit(".", 1)
        swapped = tag[:-1] + ("A" if tag[-1] != "A" else "B")
        with self.assertRaises(CursorError):
            c.decode(body + "." + swapped)

    def test_missing_separator_rejected(self):
        c = Cursor(b"k" * 32)
        with self.assertRaises(CursorError):
            c.decode("nodothere")

    def test_garbage_rejected(self):
        c = Cursor(b"k" * 32)
        with self.assertRaises(CursorError):
            c.decode("!!!.@@@")

    def test_non_string_token_rejected(self):
        c = Cursor(b"k" * 32)
        with self.assertRaises(CursorError):
            c.decode(b"bytes-not-str")

    def test_payload_without_fields_rejected(self):
        c = Cursor(b"k" * 32)
        raw = json.dumps({"nope": 1}, separators=(",", ":")).encode()
        from cursor_page.core import _b64encode, _sign
        token = _b64encode(raw) + "." + _b64encode(_sign(c._key, raw))
        with self.assertRaises(CursorError):
            c.decode(token)

    def test_bool_timestamp_rejected(self):
        c = Cursor(b"k" * 32)
        raw = json.dumps({"p": {"id": 1}, "t": True}, separators=(",", ":")).encode()
        from cursor_page.core import _b64encode, _sign
        token = _b64encode(raw) + "." + _b64encode(_sign(c._key, raw))
        with self.assertRaises(CursorError):
            c.decode(token)


class TestExpiry(unittest.TestCase):
    def test_not_expired_within_ttl(self):
        clk = FakeClock(1000.0)
        c = Cursor(b"k" * 32, ttl=60, clock=clk)
        token = c.encode({"id": 1})
        clk.advance(59)
        self.assertEqual(c.decode(token), {"id": 1})

    def test_expired_after_ttl(self):
        clk = FakeClock(1000.0)
        c = Cursor(b"k" * 32, ttl=60, clock=clk)
        token = c.encode({"id": 1})
        clk.advance(61)
        with self.assertRaises(CursorError):
            c.decode(token)

    def test_future_timestamp_rejected(self):
        clk = FakeClock(1000.0)
        c = Cursor(b"k" * 32, ttl=60, clock=clk)
        token = c.encode({"id": 1})
        # A different cursor whose clock is behind sees the token as future.
        behind = Cursor(b"k" * 32, ttl=60, clock=FakeClock(999.0))
        with self.assertRaises(CursorError):
            behind.decode(token)

    def test_no_ttl_never_expires(self):
        clk = FakeClock(0.0)
        c = Cursor(b"k" * 32, ttl=None, clock=clk)
        token = c.encode({"id": 1})
        clk.advance(10_000_000)
        self.assertEqual(c.decode(token), {"id": 1})


class TestDecodeCursorHelper(unittest.TestCase):
    def test_helper_matches_class(self):
        key = b"k" * 32
        token = Cursor(key).encode({"id": 7})
        self.assertEqual(decode_cursor(token, key), {"id": 7})

    def test_helper_respects_ttl(self):
        clk = FakeClock(0.0)
        key = b"k" * 32
        token = Cursor(key, clock=clk).encode({"id": 7})
        clk.advance(100)
        with self.assertRaises(CursorError):
            decode_cursor(token, key, ttl=50, clock=clk)


def urllib_quote_safe(s):
    import urllib.parse
    return urllib.parse.quote(s, safe="")


if __name__ == "__main__":
    unittest.main()
