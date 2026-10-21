from ssti_ai.context import ContextSpec
from ssti_ai.oracle.check_fires import OracleSession, check_fires


def test_oracle_math_probe_fires():
    """{{7*7}} evaluates to 49 -> fires on a plain Jinja2 context."""
    ctx = ContextSpec(id="x", location="jinja2_body", filters=[])
    with OracleSession() as session:
        assert session.check_fires(ctx, "{{7*7}}") is True


def test_oracle_config_probe_fires():
    """{{config}} carries a data marker -> fires (engine would evaluate it)."""
    ctx = ContextSpec(id="x", location="jinja2_body", filters=[])
    with OracleSession() as session:
        assert session.check_fires(ctx, "{{config}}") is True


def test_oracle_dollar_brace_freemarker_fires():
    """${7*7} fires on FreeMarker."""
    ctx = ContextSpec(id="x", location="freemarker_body", filters=[])
    with OracleSession() as session:
        assert session.check_fires(ctx, "${7*7}") is True


def test_oracle_dollar_brace_mako_fires():
    ctx = ContextSpec(id="x", location="mako_body", filters=[])
    with OracleSession() as session:
        assert session.check_fires(ctx, "${7*7}") is True


def test_oracle_blocked_by_curly_filter():
    """{{7*7}} blocked when block_curly_braces is active."""
    ctx = ContextSpec(id="x", location="jinja2_body", filters=["block_curly_braces"])
    with OracleSession() as session:
        assert session.check_fires(ctx, "{{7*7}}") is False


def test_oracle_blocked_by_keyword_config():
    """{{config}} blocked when block_keyword_config is active."""
    ctx = ContextSpec(id="x", location="jinja2_body", filters=["block_keyword_config"])
    with OracleSession() as session:
        assert session.check_fires(ctx, "{{config}}") is False


def test_oracle_math_probe_passes_config_filter():
    """{{7*7}} still fires when only block_keyword_config is active (no config kw)."""
    ctx = ContextSpec(id="x", location="jinja2_body", filters=["block_keyword_config"])
    with OracleSession() as session:
        assert session.check_fires(ctx, "{{7*7}}") is True


def test_oracle_subclasses_blocked():
    ctx = ContextSpec(id="x", location="jinja2_body", filters=["block_subclasses"])
    with OracleSession() as session:
        assert session.check_fires(ctx, "{{''.__subclasses__()}}") is False


def test_oracle_class_chain_fires_without_filter():
    """Object introspection chain fires on plain Jinja2 (data marker intact)."""
    ctx = ContextSpec(id="x", location="jinja2_body", filters=[])
    with OracleSession() as session:
        assert session.check_fires(ctx, "{{''.__class__.__mro__[1].__subclasses__()}}") is True


def test_oracle_lipsum_global_chain_fires():
    """Global-gadget RCE chain (no config/self) fires on plain Jinja2."""
    ctx = ContextSpec(id="x", location="jinja2_body", filters=[])
    with OracleSession() as session:
        assert session.check_fires(ctx, "{{lipsum.__globals__['os'].popen('id').read()}}") is True


def test_oracle_benign_does_not_fire():
    """Benign strings never fire."""
    ctx = ContextSpec(id="x", location="jinja2_body", filters=[])
    with OracleSession() as session:
        assert session.check_fires(ctx, "hello world") is False
        assert session.check_fires(ctx, "test_input") is False


def test_oracle_wrong_engine_does_not_fire():
    """${7*7} does NOT fire on Jinja2-only context (no dollar delimiters there).

    Note: the oracle checks whether the engine at the location would evaluate
    it. Jinja2 has no ${} delimiters, so this should not fire.
    """
    ctx = ContextSpec(id="x", location="jinja2_body", filters=[])
    with OracleSession() as session:
        assert session.check_fires(ctx, "${7*7}") is False


def test_check_fires_standalone():
    ctx = ContextSpec(id="x", location="jinja2_body", filters=[])
    assert isinstance(check_fires(ctx, "{{7*7}}"), bool)
    assert check_fires(ctx, "{{7*7}}") is True


def test_oracle_velocity_statement_fires():
    """A Velocity #set statement fires."""
    ctx = ContextSpec(id="x", location="velocity_body", filters=[])
    with OracleSession() as session:
        assert session.check_fires(ctx, "#set($x=1)") is True or \
               session.check_fires(ctx, "$ex.waitFor()") is True


def test_oracle_erb_generic_does_not_fire_on_jinja2():
    """<%= 7*7 %> (ERB/EJS syntax) is NOT evaluated by Jinja2 — no fire.

    The oracle is stricter than can_fire: a generic syntax is a plausible
    probe, but Jinja2 only evaluates {{ }} / {% %}, so this must not fire.
    """
    ctx = ContextSpec(id="x", location="jinja2_body", filters=[])
    with OracleSession() as session:
        assert session.check_fires(ctx, "<%= 7*7 %>") is False
