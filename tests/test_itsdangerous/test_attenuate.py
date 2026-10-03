from __future__ import annotations

import pytest

from itsdangerous import AttenuableToken
from itsdangerous import BadData
from itsdangerous import BadSignature
from itsdangerous import CaveatNotSatisfied
from itsdangerous import MaxBytesCaveat
from itsdangerous import OpsCaveat
from itsdangerous import PathPrefixCaveat
from itsdangerous import RequestContext
from itsdangerous import TooManyCaveats
from itsdangerous import UnknownCaveat
from itsdangerous.attenuate import DEFAULT_MAX_CAVEATS
from itsdangerous.attenuate import _frame

KEY = b"top-secret-download-key"


def make_chain():
    """Root token, then two levels of delegation."""
    root = AttenuableToken.create(KEY, "download:42")
    level1 = root.attenuate(PathPrefixCaveat("/data/team/"))
    level2 = level1.attenuate(OpsCaveat({"read", "stat"}))
    level3 = level2.attenuate(MaxBytesCaveat(1024))
    return root, level1, level2, level3


def roundtrip(token: AttenuableToken) -> AttenuableToken:
    return AttenuableToken.deserialize(token.serialize())


class TestRootToken:
    def test_root_verifies_with_no_caveats(self):
        root, _, _, _ = make_chain()
        perms = roundtrip(root).verify(KEY, RequestContext())

        assert perms.path_prefix == "/"
        assert perms.ops is None
        assert perms.max_bytes is None

    def test_wrong_key_rejected(self):
        root, _, _, _ = make_chain()

        with pytest.raises(BadSignature):
            roundtrip(root).verify(b"other-key", RequestContext())

    def test_serialize_roundtrip_preserves_chain(self):
        _, _, _, level3 = make_chain()
        loaded = roundtrip(level3)

        assert loaded.identifier == b"download:42"
        assert len(loaded.caveats) == 3
        assert loaded.signature == level3.signature
        assert loaded.serialize() == level3.serialize()


class TestDelegation:
    def test_two_level_delegation(self):
        _, _, _, level3 = make_chain()
        context = RequestContext(
            path="/data/team/reports/q3.csv", op="read", num_bytes=512
        )
        perms = roundtrip(level3).verify(KEY, context)

        assert perms.path_prefix == "/data/team"
        assert perms.ops == frozenset({"read", "stat"})
        assert perms.max_bytes == 1024

    def test_holder_can_only_tighten(self):
        """A downstream holder appends further restrictions without the
        key; the chain still verifies."""
        _, _, _, level3 = make_chain()
        level4 = roundtrip(level3).attenuate(OpsCaveat({"read"}))
        level4 = level4.attenuate(MaxBytesCaveat(100))
        context = RequestContext(path="/data/team/a.csv", op="read", num_bytes=100)
        perms = roundtrip(level4).verify(KEY, context)

        # Ops intersect, byte cap takes the minimum.
        assert perms.ops == frozenset({"read"})
        assert perms.max_bytes == 100

    @pytest.mark.parametrize(
        "context",
        [
            # Path escapes the prefix.
            RequestContext(path="/data/other/a.csv", op="read", num_bytes=1),
            # String-prefix is not enough: matching is per segment.
            RequestContext(path="/data/teamwork/a.csv", op="read", num_bytes=1),
            # Operation not in the set.
            RequestContext(path="/data/team/a.csv", op="write", num_bytes=1),
            # Byte count over the cap.
            RequestContext(path="/data/team/a.csv", op="read", num_bytes=1025),
        ],
        ids=["path-escape", "segment-boundary", "op-denied", "bytes-exceeded"],
    )
    def test_unsatisfied_caveat_rejected(self, context):
        _, _, _, level3 = make_chain()

        with pytest.raises(CaveatNotSatisfied):
            roundtrip(level3).verify(KEY, context)


class TestTampering:
    def test_removing_middle_caveat_breaks_signature(self):
        """The example attack: a holder tries to drop the intermediate
        ops restriction while keeping the final signature."""
        _, _, _, level3 = make_chain()
        loaded = roundtrip(level3)
        del loaded.caveats[1]

        with pytest.raises(BadSignature):
            loaded.verify(
                KEY, RequestContext(path="/data/team/a", op="write", num_bytes=1)
            )

    def test_reordering_caveats_breaks_signature(self):
        _, _, _, level3 = make_chain()
        loaded = roundtrip(level3)
        loaded.caveats[0], loaded.caveats[1] = (
            loaded.caveats[1],
            loaded.caveats[0],
        )

        with pytest.raises(BadSignature):
            loaded.verify(
                KEY, RequestContext(path="/data/team/a", op="read", num_bytes=1)
            )

    def test_rewriting_caveat_breaks_signature(self):
        _, _, _, level3 = make_chain()
        loaded = roundtrip(level3)
        loaded.caveats[0] = PathPrefixCaveat("/")

        with pytest.raises(BadSignature):
            loaded.verify(KEY, RequestContext(path="/", op="read", num_bytes=1))

    def test_replacing_signature_breaks_verification(self):
        root, _, _, _ = make_chain()
        other = AttenuableToken.create(KEY, "download:other")
        forged = AttenuableToken(root.identifier, [], other.signature)

        with pytest.raises(BadSignature):
            forged.verify(KEY, RequestContext())


class TestPathNormalization:
    @pytest.mark.parametrize(
        "path",
        [
            "/data/team",
            "/data/team/",
            "//data//team//",
            "/data/./team",
            "/data/x/../team",
            "/data/team/sub/../../team",
        ],
    )
    def test_equivalent_paths_match(self, path):
        _, level1, _, _ = make_chain()
        perms = roundtrip(level1).verify(KEY, RequestContext(path=path))
        assert perms.path_prefix == "/data/team"

    def test_dotdot_cannot_escape_prefix(self):
        _, level1, _, _ = make_chain()

        with pytest.raises(CaveatNotSatisfied):
            roundtrip(level1).verify(
                KEY, RequestContext(path="/data/team/../secret")
            )


class TestUnknownCaveat:
    def make_unknown_token(self):
        root, _, _, _ = make_chain()
        raw = _frame([b"future-kind", b"anything"])
        import itsdangerous.attenuate as atk

        caveat = atk._RawCaveat(raw)
        return root.attenuate(caveat)

    def test_unknown_caveat_default_denies(self):
        token = self.make_unknown_token()

        with pytest.raises(UnknownCaveat):
            roundtrip(token).verify(KEY, RequestContext())

    def test_unknown_caveat_survives_further_attenuation(self):
        """The chain stays verifiable around unknown caveats, but
        verification still refuses them."""
        token = self.make_unknown_token().attenuate(MaxBytesCaveat(1))

        with pytest.raises(UnknownCaveat):
            roundtrip(token).verify(
                KEY, RequestContext(path="/", op="", num_bytes=1)
            )


class TestChainLimit:
    def test_attenuate_enforces_limit(self):
        token = AttenuableToken.create(KEY, "id")

        for _ in range(DEFAULT_MAX_CAVEATS):
            token = token.attenuate(MaxBytesCaveat(1))

        with pytest.raises(TooManyCaveats):
            token.attenuate(MaxBytesCaveat(1))

    def test_deserialize_enforces_limit(self):
        token = AttenuableToken.create(KEY, "id")

        for _ in range(DEFAULT_MAX_CAVEATS + 1):
            token = token.attenuate(
                MaxBytesCaveat(1), max_caveats=DEFAULT_MAX_CAVEATS + 1
            )

        with pytest.raises(TooManyCaveats):
            AttenuableToken.deserialize(token.serialize())

    def test_verify_enforces_limit_before_checking(self):
        token = AttenuableToken.create(KEY, "id")

        for _ in range(3):
            token = token.attenuate(MaxBytesCaveat(1), max_caveats=10)

        with pytest.raises(TooManyCaveats):
            roundtrip(token).verify(KEY, RequestContext(), max_caveats=2)


class TestSerialization:
    def test_length_prefixed_fields_are_unambiguous(self):
        assert _frame([b"ab", b"c"]) != _frame([b"a", b"bc"])

    def test_ops_caveat_serialization_is_canonical(self):
        assert OpsCaveat({"b", "a"}).serialize() == OpsCaveat({"a", "b"}).serialize()

    def test_distinct_ops_sets_differ(self):
        assert OpsCaveat({"ab", "c"}).serialize() != OpsCaveat(
            {"a", "bc"}
        ).serialize()

    def test_malformed_token_rejected(self):
        with pytest.raises(BadData):
            AttenuableToken.deserialize("not-a-token")

        with pytest.raises(BadData):
            AttenuableToken.deserialize("atk1.only-two")

    def test_truncated_caveat_rejected(self):
        root, _, _, _ = make_chain()
        token = root.attenuate(MaxBytesCaveat(10))
        parts = token.serialize().split(".")
        # Corrupt the caveat payload.
        parts[2] = parts[2][:-2]

        with pytest.raises(BadData):
            AttenuableToken.deserialize(".".join(parts))
