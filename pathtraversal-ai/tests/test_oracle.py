"""Tests for the file-system path traversal oracle (oracle/check_fires.py)."""
from __future__ import annotations

from pathtraversal_ai.context import ContextSpec
from pathtraversal_ai.oracle.check_fires import OracleSession, check_fires


class TestOracleSessionBasics:
    def test_fires_on_classic_traversal(self):
        # '../secret.txt' escapes base/ and reads the planted marker file.
        ctx = ContextSpec(id="x", location="file_read", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "../../../secret.txt") is True

    def test_fires_on_absolute_unix_path(self):
        # The oracle plants a marker at <tmpdir>/etc/passwd; an absolute
        # /etc/passwd payload resolves to it after sandbox confinement.
        ctx = ContextSpec(id="x", location="file_read", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "/etc/passwd") is True

    def test_fires_on_php_wrapper(self):
        ctx = ContextSpec(id="x", location="file_include", filters=[])
        with OracleSession() as session:
            assert session.check_fires(
                ctx, "php://filter/convert.base64-encode/resource=index.php"
            ) is True

    def test_fires_on_file_scheme(self):
        ctx = ContextSpec(id="x", location="file_read", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "file:///etc/passwd") is True

    def test_does_not_fire_on_safe_filename(self):
        ctx = ContextSpec(id="x", location="file_read", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "safe_file.txt") is False

    def test_does_not_fire_on_empty(self):
        ctx = ContextSpec(id="x", location="file_read", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "") is False

    def test_benign_text_skipped_by_can_fire(self):
        ctx = ContextSpec(id="x", location="file_read", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "hello world") is False


class TestOracleFilters:
    def test_strip_dotdot_blocks_plain_traversal(self):
        # With strip_dotdot, '../' is removed so the path no longer escapes base.
        ctx = ContextSpec(
            id="x", location="file_read", filters=["strip_dotdot"]
        )
        with OracleSession() as session:
            # '../../secret.txt' -> 'secret.txt' stays in base (no marker there).
            assert session.check_fires(ctx, "../../secret.txt") is False

    def test_block_absolute_blocks_root(self):
        ctx = ContextSpec(
            id="x", location="file_read", filters=["block_absolute"]
        )
        with OracleSession() as session:
            assert session.check_fires(ctx, "/etc/passwd") is False

    def test_basename_only_blocks_traversal(self):
        ctx = ContextSpec(
            id="x", location="file_read", filters=["basename_only"]
        )
        with OracleSession() as session:
            # basename strips dirs -> stays in base.
            assert session.check_fires(ctx, "../../../etc/passwd") is False

    def test_block_null_byte_blocks_null(self):
        ctx = ContextSpec(
            id="x", location="file_include", filters=["block_null_byte"]
        )
        with OracleSession() as session:
            assert session.check_fires(ctx, "/etc/passwd%00") is False

    def test_url_decode_enables_encoded_traversal(self):
        # url_decode turns ..%2f into ../ so the traversal fires.
        ctx = ContextSpec(
            id="x", location="file_read", filters=["url_decode"]
        )
        with OracleSession() as session:
            # The encoded path decodes to a relative traversal escaping base.
            assert session.check_fires(ctx, "..%2f..%2f..%2fsecret.txt") is True

    def test_smuggled_traversal_bypasses_strip_dotdot(self):
        # '....//secret.txt' survives a single non-recursive strip_dotdot:
        # one pass -> '..secret.txt'... actually '....//' -> '../' is left,
        # which still escapes. The smuggled payload bypasses the weak filter.
        ctx = ContextSpec(
            id="x", location="file_read", filters=["strip_dotdot"]
        )
        with OracleSession() as session:
            # '....//....//....//secret.txt': single strip leaves traversal.
            assert session.check_fires(ctx, "....//....//....//secret.txt") is True

    def test_strip_dotdot_recursive_blocks_smuggled(self):
        # Recursive strip collapses ALL '../' including smuggled ones.
        ctx = ContextSpec(
            id="x", location="file_read", filters=["strip_dotdot_recursive"]
        )
        with OracleSession() as session:
            assert session.check_fires(ctx, "....//....//....//secret.txt") is False


class TestOracleLocations:
    def test_file_include_fires_on_traversal(self):
        ctx = ContextSpec(id="i", location="file_include", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "../../../secret.txt") is True

    def test_download_param_fires_on_absolute(self):
        ctx = ContextSpec(id="d", location="download_param", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "/etc/passwd") is True

    def test_template_path_fires_on_traversal(self):
        ctx = ContextSpec(id="t", location="template_path", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "../../../secret.txt") is True


class TestStandaloneCheckFires:
    def test_standalone_fires_on_traversal(self):
        ctx = ContextSpec(id="x", location="file_read", filters=[])
        assert check_fires(ctx, "../../../secret.txt") is True

    def test_standalone_does_not_fire_on_safe(self):
        ctx = ContextSpec(id="x", location="file_read", filters=[])
        assert check_fires(ctx, "safe_file.txt") is False

    def test_standalone_returns_bool(self):
        ctx = ContextSpec(id="x", location="file_read", filters=[])
        assert isinstance(check_fires(ctx, "../../../secret.txt"), bool)
