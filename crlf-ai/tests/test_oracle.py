from crlf_ai.context import ContextSpec
from crlf_ai.oracle.check_fires import OracleSession, check_fires


def test_check_fires_encoded_crlf_set_cookie_on_plain_context():
    """%0d%0aSet-Cookie: evil=1 fires when no filters decode/block."""
    ctx = ContextSpec(id="x", location="response_header", filters=[])
    assert check_fires(ctx, "%0d%0aSet-Cookie: evil=1") is True


def test_check_fires_plain_text_does_not_fire():
    """A benign value with no CRLF bytes must not fire."""
    ctx = ContextSpec(id="x", location="response_header", filters=[])
    assert check_fires(ctx, "just a normal value") is False


def test_check_fires_block_crlf_rejects_literal_pair():
    """block_crlf rejects a literal \\r\\n, so the payload does not fire."""
    ctx = ContextSpec(id="x", location="response_header", filters=["block_crlf"])
    assert check_fires(ctx, "\r\nSet-Cookie: evil=1") is False


def test_check_fires_url_decode_enables_encoded_payload():
    """With url_decode, an encoded %0d%0a becomes \\r\\n and fires."""
    ctx = ContextSpec(id="x", location="response_header", filters=["url_decode"])
    assert check_fires(ctx, "%0d%0aSet-Cookie: evil=1") is True


def test_check_fires_decode_then_block_blocks_encoded_payload():
    """url_decode + block_crlf: decode yields \\r\\n, then block_crlf rejects."""
    ctx = ContextSpec(id="x", location="response_header",
                      filters=["url_decode", "block_crlf"])
    assert check_fires(ctx, "%0d%0aSet-Cookie: evil=1") is False


def test_check_fires_single_cr_bypasses_block_crlf():
    """block_crlf only blocks the literal \\r\\n PAIR; a single CR (%0d) or LF
    (%0a) slips through and still splits a header line in tolerant parsers, so
    the payload fires. This is the classic 'block the pair only' bypass."""
    ctx = ContextSpec(id="x", location="response_header", filters=["block_crlf"])
    assert check_fires(ctx, "%0dSet-Cookie: evil=1") is True
    assert check_fires(ctx, "%0aSet-Cookie: evil=1") is True


def test_check_fires_double_encoded_blocked_by_decode_plus_block_crlf():
    """Double-encoded %250d%250a: the oracle pre-unquotes once (-> %0d%0a) then
    url_decode runs again on the reflected value (-> \\r\\n literal), which
    block_crlf then rejects. So the bypass does NOT work against decode+block_crlf."""
    ctx = ContextSpec(id="x", location="response_header",
                      filters=["url_decode", "block_crlf"])
    assert check_fires(ctx, "%250d%250aSet-Cookie: evil=1") is False


def test_check_fires_response_body_fires():
    """Response body location fires on a double-CRLF body injection."""
    ctx = ContextSpec(id="x", location="response_body", filters=[])
    assert check_fires(ctx, "%0d%0a%0d%0a<script>alert(1)</script>") is True


def test_check_fires_returns_bool():
    ctx = ContextSpec(id="x", location="response_header", filters=[])
    assert isinstance(check_fires(ctx, "%0d%0aSet-Cookie: evil=1"), bool)


def test_oracle_session_context_manager_api():
    """OracleSession mirrors the SSRF API: usable as a context manager."""
    ctx = ContextSpec(id="x", location="response_header", filters=[])
    with OracleSession() as session:
        assert session.check_fires(ctx, "%0d%0aSet-Cookie: evil=1") is True
        assert session.check_fires(ctx, "normal value") is False


def test_oracle_session_listener_port_ignored():
    """listener_port is accepted and ignored (no network listener for CRLF)."""
    s = OracleSession(listener_port=12345)
    assert s.listener_port == 12345
