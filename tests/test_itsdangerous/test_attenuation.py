import pytest

from itsdangerous.attenuation import _lp
from itsdangerous.attenuation import Attenuator
from itsdangerous.attenuation import ByteLimit
from itsdangerous.attenuation import normalize_path
from itsdangerous.attenuation import OperationSet
from itsdangerous.attenuation import PathPrefix
from itsdangerous.attenuation import RequestContext
from itsdangerous.encoding import base64_encode
from itsdangerous.exc import BadAttenuatedToken
from itsdangerous.exc import BadSignature
from itsdangerous.exc import CaveatNotSatisfied


@pytest.fixture()
def attenuator():
    return Attenuator("root-secret")


def read_reports():
    return RequestContext(path="/reports/2026/q3.pdf", operation="read", size=512)


class TestRootToken:
    def test_roundtrip(self, attenuator):
        token = attenuator.mint("file:q3.pdf")
        assert attenuator.verify(token, RequestContext()) == b"file:q3.pdf"

    def test_tampered_payload(self, attenuator):
        token = attenuator.mint("file:q3.pdf")
        parts = token.split(".")
        parts[1] = base64_encode(b"file:q4.pdf").decode("ascii")

        with pytest.raises(BadSignature):
            attenuator.verify(".".join(parts), RequestContext())

    def test_mint_with_caveats(self, attenuator):
        token = attenuator.mint(
            "file:q3.pdf", [PathPrefix("/reports"), OperationSet({"read"})]
        )
        assert attenuator.verify(token, read_reports()) == b"file:q3.pdf"


class TestDelegation:
    def test_two_level_delegation(self, attenuator):
        # Root token for the whole reports tree.
        root = attenuator.mint("account:7", [PathPrefix("/reports")])
        # First delegate narrows the path and the operations.
        level1 = attenuator.attenuate(root, OperationSet({"read", "list"}))
        level1 = attenuator.attenuate(level1, PathPrefix("/reports/2026"))
        # Second delegate narrows further and caps the size.
        level2 = attenuator.attenuate(level1, OperationSet({"read"}))
        level2 = attenuator.attenuate(level2, ByteLimit(1024))

        assert attenuator.verify(level2, read_reports()) == b"account:7"

    def test_downstream_cannot_widen(self, attenuator):
        token = attenuator.mint("account:7", [PathPrefix("/reports/2026")])
        # Appending a broader prefix does not loosen the earlier one.
        token = attenuator.attenuate(token, PathPrefix("/"))

        with pytest.raises(CaveatNotSatisfied):
            attenuator.verify(
                token, RequestContext(path="/reports/2025/q3.pdf")
            )

    def test_remove_middle_caveat(self, attenuator):
        token = attenuator.mint("account:7", [PathPrefix("/reports")])
        token = attenuator.attenuate(token, OperationSet({"read"}))
        token = attenuator.attenuate(token, ByteLimit(1024))
        parts = token.split(".")
        # Drop the middle "op-in" caveat, keep the final signature.
        del parts[3]

        with pytest.raises(BadSignature):
            attenuator.verify(".".join(parts), read_reports())

    def test_reorder_caveats(self, attenuator):
        token = attenuator.mint("account:7")
        token = attenuator.attenuate(token, PathPrefix("/reports"))
        token = attenuator.attenuate(token, OperationSet({"read"}))
        parts = token.split(".")
        parts[2], parts[3] = parts[3], parts[2]

        with pytest.raises(BadSignature):
            attenuator.verify(".".join(parts), read_reports())

    def test_rewrite_caveat(self, attenuator):
        token = attenuator.mint("account:7", [PathPrefix("/reports/2026")])
        parts = token.split(".")
        parts[2] = base64_encode(PathPrefix("/reports").to_bytes()).decode("ascii")

        with pytest.raises(BadSignature):
            attenuator.verify(".".join(parts), read_reports())


class TestCaveatSemantics:
    def test_path_normalization(self):
        assert normalize_path("/a//b/./c/../d/") == ("a", "b", "d")
        assert normalize_path("../a") == ("a",)

    def test_path_prefix_matches_normalized_segments(self, attenuator):
        token = attenuator.mint("x", [PathPrefix("/reports/2026")])
        context = RequestContext(path="/reports/./2026//q3.pdf")
        assert attenuator.verify(token, context) == b"x"

    def test_path_prefix_segment_boundary(self, attenuator):
        token = attenuator.mint("x", [PathPrefix("/reports/2026")])

        with pytest.raises(CaveatNotSatisfied):
            attenuator.verify(token, RequestContext(path="/reports/2026-old"))

    def test_path_prefix_dotdot_escape(self, attenuator):
        token = attenuator.mint("x", [PathPrefix("/reports/2026")])

        with pytest.raises(CaveatNotSatisfied):
            attenuator.verify(
                token, RequestContext(path="/reports/2026/../../etc/passwd")
            )

    def test_operations_intersect(self, attenuator):
        token = attenuator.mint("x", [OperationSet({"read", "list"})])
        token = attenuator.attenuate(token, OperationSet({"read"}))
        context = RequestContext(operation="read")
        assert attenuator.verify(token, context) == b"x"

        with pytest.raises(CaveatNotSatisfied):
            attenuator.verify(token, RequestContext(operation="list"))

    def test_byte_limit_takes_minimum(self, attenuator):
        token = attenuator.mint("x", [ByteLimit(2048)])
        token = attenuator.attenuate(token, ByteLimit(1024))
        assert attenuator.verify(token, RequestContext(size=1024)) == b"x"

        with pytest.raises(CaveatNotSatisfied):
            attenuator.verify(token, RequestContext(size=1500))

    def test_missing_context_field_denies(self, attenuator):
        token = attenuator.mint("x", [ByteLimit(1024)])

        with pytest.raises(CaveatNotSatisfied):
            attenuator.verify(token, RequestContext())


class TestUnknownCaveat:
    def test_unknown_kind_rejected(self, attenuator):
        # Craft a well-formed chain carrying an unknown caveat kind.
        payload = b"x"
        sig = attenuator._root_signature(payload)
        caveat_data = _lp(b"third-party") + _lp(b"discharge me elsewhere")
        sig = attenuator._extend(sig, caveat_data)
        token = ".".join(
            [
                "v1",
                base64_encode(payload).decode("ascii"),
                base64_encode(caveat_data).decode("ascii"),
                base64_encode(sig).decode("ascii"),
            ]
        )

        with pytest.raises(BadAttenuatedToken, match="Unknown caveat"):
            attenuator.verify(token, RequestContext())

    def test_empty_caveat_rejected(self, attenuator):
        token = attenuator.mint("x")
        parts = token.split(".")
        sig = attenuator._extend(attenuator._root_signature(b"x"), b"")
        parts.insert(-1, "")
        parts[-1] = base64_encode(sig).decode("ascii")

        with pytest.raises(BadAttenuatedToken):
            attenuator.verify(".".join(parts), RequestContext())


class TestChainLimit:
    def test_mint_over_limit(self):
        attenuator = Attenuator("k", max_caveats=2)

        with pytest.raises(ValueError):
            attenuator.mint("x", [PathPrefix("/a")] * 3)

    def test_attenuate_over_limit(self):
        attenuator = Attenuator("k", max_caveats=2)
        token = attenuator.mint("x", [PathPrefix("/a"), PathPrefix("/a/b")])

        with pytest.raises(BadAttenuatedToken, match="Too many caveats"):
            attenuator.attenuate(token, ByteLimit(1))

    def test_verify_over_limit(self):
        small = Attenuator("k", max_caveats=2)
        big = Attenuator("k", max_caveats=10)
        token = big.mint("x", [PathPrefix("/a")] * 3)

        with pytest.raises(BadAttenuatedToken, match="Too many caveats"):
            small.verify(token, RequestContext(path="/a/b"))


class TestSerialization:
    def test_fields_unambiguous(self):
        # ("ab", "c") and ("a", "bc") must not collide.
        assert _lp(b"ab") + _lp(b"c") != _lp(b"a") + _lp(b"bc")

    def test_malformed_token(self, attenuator):
        with pytest.raises(BadAttenuatedToken):
            attenuator.verify("not-a-token", RequestContext())

        with pytest.raises(BadAttenuatedToken):
            attenuator.verify("v1.eHh+.abc", RequestContext())

    def test_truncated_caveat_field(self, attenuator):
        payload = b"x"
        caveat_data = _lp(b"path-prefix") + b"\x00\x00"
        sig = attenuator._root_signature(payload)
        sig = attenuator._extend(sig, caveat_data)
        token = ".".join(
            [
                "v1",
                base64_encode(payload).decode("ascii"),
                base64_encode(caveat_data).decode("ascii"),
                base64_encode(sig).decode("ascii"),
            ]
        )

        with pytest.raises(BadAttenuatedToken, match="Truncated"):
            attenuator.verify(token, RequestContext())
