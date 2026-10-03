"""Attenuable bearer tokens with first-party caveats.

An :class:`AttenuableToken` starts as a root token signed with a secret
key. A holder may *attenuate* it by appending caveats that further
restrict how the token can be used, without knowing the key. Each
caveat is folded into a chained HMAC signature::

    sig_0 = HMAC(key, frame(domain, identifier))
    sig_n = HMAC(sig_n-1, caveat_n)

Because every caveat depends on the signature of all previous caveats,
removing, reordering, or rewriting any caveat invalidates the final
signature. A holder can only ever append new restrictions, never loosen
existing ones. Only first-party caveats are supported; there is no
third-party discharge mechanism.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import typing as t
from dataclasses import dataclass

from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import want_bytes
from .exc import BadData
from .exc import BadSignature

#: Default maximum number of caveats a token may carry. This bounds the
#: work a verifier performs per token so a maliciously long chain cannot
#: cause unbounded HMAC computation.
DEFAULT_MAX_CAVEATS = 32

_TOKEN_VERSION = "atk1"
_DOMAIN = b"itsdangerous.attenuate.v1"
_uint32 = struct.Struct(">I")
_uint64 = struct.Struct(">Q")


class BadCaveat(BadData):
    """Base class for errors raised while parsing or evaluating
    caveats.
    """


class UnknownCaveat(BadCaveat):
    """A caveat kind was encountered that this verifier does not
    understand. Unknown caveats are never skipped; they always cause
    verification to fail (default deny).
    """


class CaveatNotSatisfied(BadCaveat):
    """A caveat does not hold for the provided request context."""


class TooManyCaveats(BadCaveat):
    """The token carries more caveats than the configured chain length
    limit allows.
    """


def _frame(fields: t.Iterable[bytes]) -> bytes:
    """Serialize fields with explicit length prefixes so that
    concatenation is unambiguous: ``frame([b"ab", b"c"])`` differs from
    ``frame([b"a", b"bc"])``.
    """
    out = bytearray()

    for field in fields:
        out += _uint32.pack(len(field))
        out += field

    return bytes(out)


def _parse_frames(data: bytes) -> list[bytes]:
    fields: list[bytes] = []
    pos = 0

    while pos < len(data):
        if pos + _uint32.size > len(data):
            raise BadCaveat("Truncated caveat field length")

        (size,) = _uint32.unpack(data[pos : pos + _uint32.size])
        pos += _uint32.size

        if pos + size > len(data):
            raise BadCaveat("Truncated caveat field data")

        fields.append(data[pos : pos + size])
        pos += size

    return fields


def _normalize_path(path: str) -> tuple[str, ...]:
    """Normalize a URL-style path into segments. Empty and ``.``
    segments are dropped, ``..`` pops the previous segment (clamped at
    the root). Matching is done per segment, never by string prefix.
    """
    segments: list[str] = []

    for segment in path.split("/"):
        if segment in ("", "."):
            continue

        if segment == "..":
            if segments:
                segments.pop()

            continue

        segments.append(segment)

    return tuple(segments)


@dataclass(frozen=True)
class RequestContext:
    """The actual request a token is being used for. The verifier
    builds this and every caveat on the token must hold for it.
    """

    #: The normalized request path, e.g. ``"/data/team/report.csv"``.
    path: str = "/"
    #: The requested operation, e.g. ``"read"``.
    op: str = ""
    #: The number of bytes the request will transfer.
    num_bytes: int = 0


@dataclass(frozen=True)
class Permissions:
    """The effective permissions of a verified token: the combination
    of all its caveats. ``None`` means unrestricted for that dimension.
    """

    #: The most restrictive path prefix, normalized. ``"/"`` if no
    #: path caveat was present.
    path_prefix: str
    #: Intersection of all operation set caveats.
    ops: frozenset[str] | None
    #: Minimum of all byte cap caveats.
    max_bytes: int | None


class Caveat:
    """Base class for first-party caveats. Subclasses must set
    :attr:`kind` and implement :meth:`_fields` and :meth:`check`.
    """

    kind: str = ""

    def _fields(self) -> tuple[bytes, ...]:
        raise NotImplementedError()

    def check(self, context: RequestContext) -> None:
        """Raise :class:`CaveatNotSatisfied` if this caveat does not
        hold for the given request context.
        """
        raise NotImplementedError()

    def serialize(self) -> bytes:
        return _frame([self.kind.encode("ascii"), *self._fields()])

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.serialize()!r})"


class PathPrefixCaveat(Caveat):
    """Restricts the request path to a normalized segment prefix. A
    prefix of ``/data/team`` matches ``/data/team`` and
    ``/data/team/a.csv`` but not ``/data/teamwork``.
    """

    kind = "path"

    def __init__(self, prefix: str):
        self.segments: tuple[str, ...] = _normalize_path(prefix)

    @property
    def prefix(self) -> str:
        return "/" + "/".join(self.segments)

    def _fields(self) -> tuple[bytes, ...]:
        return tuple(segment.encode("utf-8") for segment in self.segments)

    @classmethod
    def _from_fields(cls, fields: list[bytes]) -> PathPrefixCaveat:
        # Normalization is idempotent, so re-joining is canonical.
        return cls("/" + "/".join(field.decode("utf-8") for field in fields))

    def check(self, context: RequestContext) -> None:
        request = _normalize_path(context.path)

        if request[: len(self.segments)] != self.segments:
            raise CaveatNotSatisfied(
                f"Path {context.path!r} is not under prefix {self.prefix!r}"
            )


class OpsCaveat(Caveat):
    """Restricts the allowed operations to a set. Chained ops caveats
    combine by intersection, so the effective set can only shrink.
    """

    kind = "ops"

    def __init__(self, ops: t.Iterable[str]):
        ops = frozenset(ops)

        if not ops or any(not op for op in ops):
            raise ValueError("OpsCaveat requires at least one non-empty operation")

        self.ops: frozenset[str] = ops

    def _fields(self) -> tuple[bytes, ...]:
        # Sorted so the serialization is canonical.
        return tuple(sorted(op.encode("utf-8") for op in self.ops))

    @classmethod
    def _from_fields(cls, fields: list[bytes]) -> OpsCaveat:
        return cls(op.decode("utf-8") for op in fields)

    def check(self, context: RequestContext) -> None:
        if context.op not in self.ops:
            raise CaveatNotSatisfied(
                f"Operation {context.op!r} is not in {sorted(self.ops)!r}"
            )


class MaxBytesCaveat(Caveat):
    """Caps the number of bytes the request may transfer. Chained caps
    combine by minimum, so the cap can only get smaller.
    """

    kind = "bytes"

    def __init__(self, limit: int):
        if limit < 0:
            raise ValueError("Byte limit must be non-negative")

        self.limit: int = limit

    def _fields(self) -> tuple[bytes, ...]:
        return (_uint64.pack(self.limit),)

    @classmethod
    def _from_fields(cls, fields: list[bytes]) -> MaxBytesCaveat:
        if len(fields) != 1 or len(fields[0]) != _uint64.size:
            raise BadCaveat("Malformed byte limit caveat")

        return cls(_uint64.unpack(fields[0])[0])

    def check(self, context: RequestContext) -> None:
        if context.num_bytes > self.limit:
            raise CaveatNotSatisfied(
                f"Request of {context.num_bytes} bytes exceeds limit"
                f" of {self.limit}"
            )


class _RawCaveat(Caveat):
    """A caveat of a kind this version does not understand. The raw
    bytes are preserved so the signature chain stays intact, but
    :meth:`check` always fails: unknown caveats are never skipped.
    """

    def __init__(self, raw: bytes):
        self.raw = raw

    def serialize(self) -> bytes:
        return self.raw

    def check(self, context: RequestContext) -> None:
        raise UnknownCaveat("Token carries a caveat of an unknown kind")


_CAVEAT_TYPES: dict[str, type[Caveat]] = {
    cls.kind: cls for cls in (PathPrefixCaveat, OpsCaveat, MaxBytesCaveat)
}


def _parse_caveat(data: bytes) -> Caveat:
    fields = _parse_frames(data)

    if not fields:
        raise BadCaveat("Empty caveat")

    try:
        kind = fields[0].decode("ascii")
    except UnicodeDecodeError:
        return _RawCaveat(data)

    cls = _CAVEAT_TYPES.get(kind)

    if cls is None:
        return _RawCaveat(data)

    try:
        return cls._from_fields(fields[1:])  # type: ignore[attr-defined]
    except (UnicodeDecodeError, ValueError) as e:
        raise BadCaveat(f"Malformed {kind!r} caveat") from e


def _root_signature(key: bytes, identifier: bytes) -> bytes:
    return hmac.new(key, _frame([_DOMAIN, identifier]), hashlib.sha256).digest()


def _chain(signature: bytes, caveat: Caveat) -> bytes:
    return hmac.new(signature, caveat.serialize(), hashlib.sha256).digest()


class AttenuableToken:
    """A bearer token whose holder can only append further
    restrictions (caveats), never remove or relax them.
    """

    def __init__(
        self,
        identifier: bytes,
        caveats: list[Caveat],
        signature: bytes,
    ):
        self.identifier = identifier
        self.caveats = caveats
        self.signature = signature

    @classmethod
    def create(cls, key: str | bytes, identifier: str | bytes) -> AttenuableToken:
        """Create a root token with no caveats. Only the key holder can
        do this.
        """
        key = want_bytes(key)
        identifier = want_bytes(identifier)
        return cls(identifier, [], _root_signature(key, identifier))

    def attenuate(
        self, caveat: Caveat, *, max_caveats: int = DEFAULT_MAX_CAVEATS
    ) -> AttenuableToken:
        """Return a new token with ``caveat`` appended. The current
        signature is all that is needed, so any holder can further
        restrict the token, but only restrict it.
        """
        if len(self.caveats) >= max_caveats:
            raise TooManyCaveats(
                f"Token already has the maximum of {max_caveats} caveats"
            )

        return AttenuableToken(
            self.identifier,
            [*self.caveats, caveat],
            _chain(self.signature, caveat),
        )

    def serialize(self) -> str:
        """Serialize to a compact string. Each part is base64 encoded
        and dot separated; fields within a caveat use length prefixes,
        so no two distinct tokens share a serialization.
        """
        parts = [
            _TOKEN_VERSION,
            base64_encode(self.identifier).decode("ascii"),
            *(base64_encode(c.serialize()).decode("ascii") for c in self.caveats),
            base64_encode(self.signature).decode("ascii"),
        ]
        return ".".join(parts)

    @classmethod
    def deserialize(
        cls, data: str | bytes, *, max_caveats: int = DEFAULT_MAX_CAVEATS
    ) -> AttenuableToken:
        """Parse a serialized token. This does not verify the
        signature; call :meth:`verify` with the key for that.
        """
        parts = want_bytes(data).decode("ascii").split(".")

        if len(parts) < 3 or parts[0] != _TOKEN_VERSION:
            raise BadData("Not an attenuable token")

        caveats = [_parse_caveat(base64_decode(part)) for part in parts[2:-1]]

        if len(caveats) > max_caveats:
            raise TooManyCaveats(
                f"Token has {len(caveats)} caveats, more than the maximum"
                f" of {max_caveats}"
            )

        return cls(
            base64_decode(parts[1]),
            caveats,
            base64_decode(parts[-1]),
        )

    def verify(
        self,
        key: str | bytes,
        context: RequestContext,
        *,
        max_caveats: int = DEFAULT_MAX_CAVEATS,
    ) -> Permissions:
        """Verify the signature chain and every caveat against the
        actual request context. Returns the effective
        :class:`Permissions`. Raises :class:`BadSignature` if the chain
        was tampered with, :class:`TooManyCaveats` if the chain exceeds
        the limit, :class:`UnknownCaveat` for unrecognized caveats, and
        :class:`CaveatNotSatisfied` if any caveat does not hold.
        """
        if len(self.caveats) > max_caveats:
            raise TooManyCaveats(
                f"Token has {len(self.caveats)} caveats, more than the maximum"
                f" of {max_caveats}"
            )

        expected = _root_signature(want_bytes(key), self.identifier)

        for caveat in self.caveats:
            expected = _chain(expected, caveat)

        if not hmac.compare_digest(expected, self.signature):
            raise BadSignature("Token signature does not match")

        path: tuple[str, ...] | None = None
        ops: frozenset[str] | None = None
        max_bytes: int | None = None

        for caveat in self.caveats:
            caveat.check(context)

            if isinstance(caveat, PathPrefixCaveat):
                # All path caveats matched the request path, so they
                # are nested; the longest is the most restrictive.
                if path is None or len(caveat.segments) > len(path):
                    path = caveat.segments
            elif isinstance(caveat, OpsCaveat):
                ops = caveat.ops if ops is None else ops & caveat.ops
            elif isinstance(caveat, MaxBytesCaveat):
                max_bytes = (
                    caveat.limit
                    if max_bytes is None
                    else min(max_bytes, caveat.limit)
                )

        return Permissions(
            path_prefix="/" + "/".join(path) if path else "/",
            ops=ops,
            max_bytes=max_bytes,
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(identifier={self.identifier!r},"
            f" caveats={self.caveats!r})"
        )
