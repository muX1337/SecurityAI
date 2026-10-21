from openredirect_ai.context import ContextSpec
from openredirect_ai.oracle.check_fires import check_fires


def test_check_fires_external_absolute():
    """An external absolute URL fires when no filters block it."""
    ctx = ContextSpec(id="x", location="redirect_param", filters=[])
    assert check_fires(ctx, "https://evil.com/") is True


def test_check_fires_protocol_relative():
    """A protocol-relative URL to an external host fires."""
    ctx = ContextSpec(id="x", location="redirect_param", filters=[])
    assert check_fires(ctx, "//evil.com/") is True


def test_check_fires_app_at_evil():
    """Userinfo bypass: app.com@evil.com redirects to evil.com -> fires."""
    ctx = ContextSpec(id="x", location="redirect_param", filters=[])
    assert check_fires(ctx, "https://app.com@evil.com/") is True


def test_check_fires_blocked_by_absolute_filter():
    """block_absolute_url rejects https://evil.com/ -> does not fire."""
    ctx = ContextSpec(id="x", location="redirect_param", filters=["block_absolute_url"])
    assert check_fires(ctx, "https://evil.com/") is False


def test_check_fires_protocol_relative_bypasses_absolute_filter():
    """//evil.com/ survives block_absolute_url and still fires."""
    ctx = ContextSpec(id="x", location="redirect_param", filters=["block_absolute_url"])
    assert check_fires(ctx, "//evil.com/") is True


def test_check_fires_url_decode_bypass():
    """url_decode decodes %2F%2Fevil.com%2F -> //evil.com/, which fires when no
    protocol-relative block follows."""
    ctx = ContextSpec(id="x", location="redirect_param", filters=["url_decode"])
    assert check_fires(ctx, "%2F%2Fevil.com%2F") is True


def test_check_fires_url_decode_then_blocked():
    """url_decode followed by block_protocol_relative: decoded // is blocked."""
    ctx = ContextSpec(id="x", location="redirect_param",
                      filters=["url_decode", "block_protocol_relative"])
    assert check_fires(ctx, "%2F%2Fevil.com%2F") is False


def test_check_fires_internal_url():
    """Internal absolute URL does not fire."""
    ctx = ContextSpec(id="x", location="redirect_param", filters=[])
    assert check_fires(ctx, "https://app.com/home") is False


def test_check_fires_not_a_url():
    """Plain text never fires."""
    ctx = ContextSpec(id="x", location="redirect_param", filters=[])
    assert check_fires(ctx, "test_input") is False


def test_check_fires_empty():
    ctx = ContextSpec(id="x", location="redirect_param", filters=[])
    assert check_fires(ctx, "") is False


def test_check_fires_works_across_locations():
    """The oracle is location-agnostic; same payload fires across locations."""
    for loc in ("redirect_param", "location_header", "return_url", "next_param"):
        ctx = ContextSpec(id="x", location=loc, filters=[])
        assert check_fires(ctx, "https://evil.com/") is True
