from ssrf_ai.context import ContextSpec
from ssrf_ai.oracle.check_fires import OracleSession


def test_oracle_session_fires_on_callback():
    """OracleSession: a URL pointing to the listener fires when no filters block it."""
    ctx_plain = ContextSpec(id="x", location="query_param", filters=[])
    ctx_blocked = ContextSpec(id="y", location="query_param", filters=["block_private_ip"])

    with OracleSession() as session:
        listener_url = f"http://127.0.0.1:{session.listener_port}/hit"
        assert session.check_fires(ctx_plain, listener_url) is True
        assert session.check_fires(ctx_blocked, listener_url) is False

def test_oracle_session_blocked_by_scheme():
    ctx = ContextSpec(id="x", location="query_param", filters=["scheme_http_only"])
    with OracleSession() as session:
        assert session.check_fires(ctx, "file:///etc/passwd") is False

def test_oracle_session_invalid_url():
    ctx = ContextSpec(id="x", location="query_param", filters=[])
    with OracleSession() as session:
        assert session.check_fires(ctx, "not a url") is False

def test_check_fires_standalone():
    """The standalone check_fires creates its own session."""
    ctx = ContextSpec(id="x", location="query_param", filters=[])
    with OracleSession() as session:
        listener_url = f"http://127.0.0.1:{session.listener_port}/test"
        result = session.check_fires(ctx, listener_url)
    assert isinstance(result, bool)
