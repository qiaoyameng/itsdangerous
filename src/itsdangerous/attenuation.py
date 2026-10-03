from __future__ import annotations

import collections.abc as cabc
import hashlib
import hmac
import re
import struct
import typing as t
from dataclasses import dataclass

from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import want_bytes
from .exc import BadAttenuatedToken
from .exc import BadSignature
from .exc import CaveatNotSatisfied

#: Domain separation tags so a token signature can never be confused
#: with a signature produced for a different purpose.
_DOMAIN_ROOT = b"itsdangerous.attenuation.v1.root"
_DOMAIN_CAVEAT = b"itsdangerous.attenuation.v1.caveat"

#: Token format version, the first segment of every token.
_VERSION = "v1"

#: Default bound on the number of caveats in a chain. Verification work
#: grows linearly with the chain, so this keeps it bounded.
DEFAULT_MAX_CAVEATS = 32

_segment_re = re.compile(r"[A-Za-z0-9_-]*\Z")
_len_struct = struct.Struct(">I")
_u64_struct = struct.Struct(">Q")


def _lp(field: bytes) -> bytes:
    """Length-prefix a field so a sequence of fields has exactly one
    canonical encoding and no concatenation ambiguity.
    """
    return _len_struct.pack(len(field)) + field


def _split_fields(data: bytes) -> list[bytes]:
    """Split length-prefixed fields, rejecting truncated or trailing
    data.
    """
    fields: list[bytes] = []
    pos = 0

    while pos < len(data):
        if pos + _len_struct.size > len(data):
            raise BadAttenuatedToken("Truncated caveat field")

        (length,) = _len_struct.unpack_from(data, pos)
        pos += _len_struct.size

        if pos + length > len(data):
            raise BadAttenuatedToken("Truncated caveat field")

        fields.append(data[pos : pos + length])
        pos += length

    return fields


def normalize_path(path: str) -> tuple[str, ...]:
    """Reduce a path to its canonical tuple of segments. Empty and
    ``.`` segments are dropped, ``..`` pops the previous segment and
    is clamped at the root.
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


@dataclass
class RequestContext:
    """The actual request a token is being verified against. Every
    caveat on the token must be satisfied by this context. A field
    that is ``None`` never satisfies a caveat that needs it.

    .. versionadded:: 2.3
    """

    path: str | None = None
    operation: str | None = None
    size: int | None = None


_caveat_types: dict[str, type[Caveat]] = {}


class Caveat:
    """Base class for first-party caveats. A caveat can only restrict
    a token further; it can never grant anything the token did not
    already allow. Subclasses are registered by their ``kind`` and
    must implement :meth:`fields`, :meth:`from_fields`, and
    :meth:`check`.

    .. versionadded:: 2.3
    """

    kind: t.ClassVar[str]

    def __init_subclass__(cls, **kwargs: t.Any) -> None:
        super().__init_subclass__(**kwargs)
        _caveat_types[cls.kind] = cls

    def fields(self) -> tuple[bytes, ...]:
        """The caveat's parameters as a tuple of byte fields."""
        raise NotImplementedError()

    @classmethod
    def from_fields(cls, fields: tuple[bytes, ...]) -> Caveat:
        """Rebuild a caveat from its parsed fields."""
        raise NotImplementedError()

    def check(self, context: RequestContext) -> None:
        """Raise :exc:`CaveatNotSatisfied` if the request context does
        not satisfy this caveat.
        """
        raise NotImplementedError()

    def to_bytes(self) -> bytes:
        """Canonical serialization: the kind followed by the fields,
        each length-prefixed.
        """
        return b"".join(_lp(f) for f in (want_bytes(self.kind), *self.fields()))

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.to_bytes()!r}>"


def _caveat_from_bytes(data: bytes) -> Caveat:
    fields = _split_fields(data)

    if not fields:
        raise BadAttenuatedToken("Empty caveat")

    try:
        kind = fields[0].decode("ascii")
    except UnicodeDecodeError as e:
        raise BadAttenuatedToken("Caveat kind is not ASCII") from e

    cls = _caveat_types.get(kind)

    if cls is None:
        # Fail closed: an unknown caveat can never be skipped.
        raise BadAttenuatedToken(f"Unknown caveat kind {kind!r}")

    try:
        return cls.from_fields(tuple(fields[1:]))
    except (UnicodeDecodeError, struct.error) as e:
        raise BadAttenuatedToken(f"Malformed {kind!r} caveat") from e


class PathPrefix(Caveat):
    """Restricts requests to paths under a prefix. Paths are
    normalized to segments before matching, so ``/a/./b`` and
    ``/a//b`` are the same path and ``..`` cannot escape the prefix.

    .. versionadded:: 2.3
    """

    kind = "path-prefix"

    def __init__(self, prefix: str):
        self.segments = normalize_path(prefix)

    def fields(self) -> tuple[bytes, ...]:
        return tuple(want_bytes(s) for s in self.segments)

    @classmethod
    def from_fields(cls, fields: tuple[bytes, ...]) -> PathPrefix:
        self = cls.__new__(cls)
        self.segments = tuple(f.decode("utf-8") for f in fields)
        return self

    def check(self, context: RequestContext) -> None:
        if context.path is None:
            raise CaveatNotSatisfied("No path in the request context")

        request = normalize_path(context.path)

        if request[: len(self.segments)] != self.segments:
            raise CaveatNotSatisfied(
                f"Path {context.path!r} is not under the required prefix"
            )


class OperationSet(Caveat):
    """Restricts requests to a set of operations. Each caveat of this
    kind must independently allow the operation, so stacking caveats
    intersects the sets.

    .. versionadded:: 2.3
    """

    kind = "op-in"

    def __init__(self, operations: cabc.Iterable[str]):
        self.operations = frozenset(operations)

        if not self.operations:
            raise ValueError("At least one operation is required")

    def fields(self) -> tuple[bytes, ...]:
        return tuple(want_bytes(op) for op in sorted(self.operations))

    @classmethod
    def from_fields(cls, fields: tuple[bytes, ...]) -> OperationSet:
        return cls(f.decode("utf-8") for f in fields)

    def check(self, context: RequestContext) -> None:
        if context.operation is None or context.operation not in self.operations:
            raise CaveatNotSatisfied(
                f"Operation {context.operation!r} is not allowed"
            )


class ByteLimit(Caveat):
    """Restricts requests to at most ``max_bytes`` bytes. Every
    caveat of this kind must be satisfied, so the effective limit is
    the smallest one in the chain.

    .. versionadded:: 2.3
    """

    kind = "size-le"

    def __init__(self, max_bytes: int):
        if max_bytes < 0:
            raise ValueError("max_bytes must not be negative")

        self.max_bytes = max_bytes

    def fields(self) -> tuple[bytes, ...]:
        return (_u64_struct.pack(self.max_bytes),)

    @classmethod
    def from_fields(cls, fields: tuple[bytes, ...]) -> ByteLimit:
        if len(fields) != 1 or len(fields[0]) != _u64_struct.size:
            raise BadAttenuatedToken("Malformed 'size-le' caveat")

        return cls(_u64_struct.unpack(fields[0])[0])

    def check(self, context: RequestContext) -> None:
        if context.size is None or context.size > self.max_bytes:
            raise CaveatNotSatisfied(
                f"Size {context.size!r} exceeds the limit of {self.max_bytes}"
            )


class Attenuator:
    """Mints, attenuates, and verifies chained tokens.

    A token carries a payload and an ordered chain of caveats. The
    root signature is ``HMAC(key, payload)``; each caveat extends the
    chain with ``HMAC(previous, caveat)``. A holder can append a
    caveat using only the current signature, so any downstream party
    can restrict the token further without the secret key, but
    removing, reordering, or rewriting an existing caveat invalidates
    every signature after it.

    Only first-party caveats are supported; there is no third-party
    discharge.

    .. versionadded:: 2.3

    :param secret_key: The root secret used to mint and verify tokens.
    :param max_caveats: Maximum caveats allowed in a chain, bounding
        verification work.
    """

    def __init__(
        self, secret_key: str | bytes, max_caveats: int = DEFAULT_MAX_CAVEATS
    ):
        self.secret_key = want_bytes(secret_key)
        self.max_caveats = max_caveats

    def _root_signature(self, payload: bytes) -> bytes:
        return hmac.new(
            self.secret_key, _DOMAIN_ROOT + _lp(payload), hashlib.sha256
        ).digest()

    @staticmethod
    def _extend(signature: bytes, caveat_data: bytes) -> bytes:
        return hmac.new(
            signature, _DOMAIN_CAVEAT + caveat_data, hashlib.sha256
        ).digest()

    def mint(
        self, payload: str | bytes, caveats: cabc.Iterable[Caveat] = ()
    ) -> str:
        """Create a root token for ``payload``, optionally already
        restricted by ``caveats``.
        """
        payload_bytes = want_bytes(payload)
        caveat_list = list(caveats)

        if len(caveat_list) > self.max_caveats:
            raise ValueError(
                f"Too many caveats, the limit is {self.max_caveats}"
            )

        signature = self._root_signature(payload_bytes)
        parts = [_VERSION, base64_encode(payload_bytes).decode("ascii")]

        for caveat in caveat_list:
            data = caveat.to_bytes()
            signature = self._extend(signature, data)
            parts.append(base64_encode(data).decode("ascii"))

        parts.append(base64_encode(signature).decode("ascii"))
        return ".".join(parts)

    def _parse(self, token: str) -> tuple[bytes, list[bytes], bytes]:
        parts = token.split(".")

        if len(parts) < 3 or parts[0] != _VERSION:
            raise BadAttenuatedToken("Malformed token")

        if any(_segment_re.match(part) is None for part in parts[1:]):
            raise BadAttenuatedToken("Malformed token segment")

        caveat_count = len(parts) - 3

        if caveat_count > self.max_caveats:
            raise BadAttenuatedToken(
                f"Too many caveats, the limit is {self.max_caveats}"
            )

        payload = base64_decode(parts[1])
        caveat_datas = [base64_decode(part) for part in parts[2:-1]]
        signature = base64_decode(parts[-1])
        return payload, caveat_datas, signature

    def attenuate(self, token: str, caveat: Caveat) -> str:
        """Append ``caveat`` to ``token`` and return the new token.
        This only needs the token's current signature, not the secret
        key, so any holder can restrict a token further. Existing
        caveats cannot be removed, reordered, or changed.
        """
        _, caveat_datas, signature = self._parse(token)

        if len(caveat_datas) >= self.max_caveats:
            raise BadAttenuatedToken(
                f"Too many caveats, the limit is {self.max_caveats}"
            )

        data = caveat.to_bytes()
        new_signature = self._extend(signature, data)
        parts = token.split(".")
        parts[-1] = base64_encode(new_signature).decode("ascii")
        parts.insert(-1, base64_encode(data).decode("ascii"))
        return ".".join(parts)

    def verify(self, token: str, context: RequestContext) -> bytes:
        """Verify ``token`` against the root key and check that every
        caveat is satisfied by ``context``. Returns the payload.
        Unknown caveats are rejected, never skipped.
        """
        payload, caveat_datas, signature = self._parse(token)
        expected = self._root_signature(payload)
        caveats: list[Caveat] = []

        for data in caveat_datas:
            caveats.append(_caveat_from_bytes(data))
            expected = self._extend(expected, data)

        if not hmac.compare_digest(expected, signature):
            raise BadSignature("Signature does not match", payload=payload)

        for caveat in caveats:
            caveat.check(context)

        return payload
