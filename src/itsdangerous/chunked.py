from __future__ import annotations

import hashlib
import json
import math
import secrets
import typing as t
from dataclasses import dataclass

from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import want_bytes
from .exc import BadData
from .signer import Signer


class ChunkError(BadData):
    """Base class for errors raised while splitting a token into chunks
    or reassembling it.

    .. versionadded:: 2.3
    """


class ForeignChunkError(ChunkError):
    """A chunk is bound to a different manifest than the one being
    reassembled. Chunks from two issuances cannot be mixed.

    .. versionadded:: 2.3
    """


class ExtraChunkError(ChunkError):
    """A chunk's position is outside the range declared by the
    manifest.

    .. versionadded:: 2.3
    """


class ConflictingChunkError(ChunkError):
    """Two different chunks claim the same position in the same
    manifest.

    .. versionadded:: 2.3
    """


class ChunkBudgetError(ChunkError):
    """The manifest declares a total length that exceeds the allowed
    budget.

    .. versionadded:: 2.3
    """


@dataclass(frozen=True)
class ChunkedMessage:
    """The result of :meth:`TokenChunker.split`.

    .. versionadded:: 2.3
    """

    #: The signed manifest. Must be stored alongside the chunks and
    #: presented to :meth:`TokenChunker.join` to reassemble.
    manifest: str

    #: The signed chunks, in order of their position.
    chunks: list[str]

    #: The message identity bound into the manifest. Random unless a
    #: deterministic one was passed to :meth:`TokenChunker.split`.
    message_id: str

    #: The number of chunks the token was split into.
    count: int

    #: The total length of the token in bytes.
    length: int

    #: The SHA-256 hex digest of the whole token.
    digest: str

    #: Chunk positions the caller should delete from storage. When a
    #: previously stored token was longer, its tail chunks would remain
    #: after storing this shorter message. Pass ``previous_count`` to
    #: :meth:`TokenChunker.split` to populate this.
    stale_indices: list[int]


@dataclass(frozen=True)
class ReassemblyResult:
    """The result of :meth:`TokenChunker.join`.

    .. versionadded:: 2.3
    """

    #: Whether all chunks were collected and verified.
    complete: bool

    #: The reassembled token. This is only populated once every chunk
    #: is present and the whole payload has been verified against the
    #: manifest, otherwise it is ``None``.
    token: bytes | None

    #: Positions that are still missing, if not complete.
    missing: list[int]

    #: Positions that were received, sorted.
    received: list[int]


class TokenChunker:
    """Split a signed token into size-limited chunks and reassemble it
    later, without any dependency on an HTTP framework. The caller
    decides where the manifest and chunks are stored; this class never
    reads or writes cookies itself.

    The manifest binds a message identity (random, or deterministic if
    given), the chunk count, the total length, and the SHA-256 digest
    of the whole token. Each chunk binds the manifest it belongs to
    and its own position, so chunks from two issuances cannot be mixed.

    :param secret_key: The secret key to sign and verify with. Can be a
        list of keys, oldest to newest, to support key rotation.
    :param salt: Extra key to combine with ``secret_key`` to distinguish
        signatures in different contexts.
    :param signer_kwargs: Keyword arguments to pass when instantiating
        the internal :class:`~itsdangerous.signer.Signer`.

    .. versionadded:: 2.3
    """

    def __init__(
        self,
        secret_key: str | bytes | t.Iterable[str] | t.Iterable[bytes],
        salt: str | bytes = b"itsdangerous.chunked",
        signer_kwargs: dict[str, t.Any] | None = None,
    ) -> None:
        self._signer = Signer(secret_key, salt=salt, **(signer_kwargs or {}))

    def split(
        self,
        token: str | bytes,
        max_chunk_bytes: int,
        message_id: str | None = None,
        previous_count: int | None = None,
    ) -> ChunkedMessage:
        """Split ``token`` into signed chunks of at most
        ``max_chunk_bytes`` payload bytes each, plus a signed manifest.

        :param token: The token to split.
        :param max_chunk_bytes: Maximum number of token bytes per chunk,
            before encoding and signing overhead.
        :param message_id: Identity bound into the manifest. Generated
            randomly if not given. Pass a deterministic value, such as
            one derived from the token, to make re-issuing the same
            token produce identical output.
        :param previous_count: Number of chunks stored for the previous
            token, used to compute :attr:`ChunkedMessage.stale_indices`
            so tail chunks of a previously longer token are deleted.
        """
        if max_chunk_bytes < 1:
            raise ValueError("max_chunk_bytes must be at least 1")

        data = want_bytes(token)
        length = len(data)
        count = max(1, math.ceil(length / max_chunk_bytes))
        digest = hashlib.sha256(data).hexdigest()

        if message_id is None:
            message_id = secrets.token_urlsafe(16)
        else:
            message_id = str(message_id)

        manifest = self._dump_payload(
            {
                "count": count,
                "digest": digest,
                "id": message_id,
                "length": length,
                "v": 1,
            }
        )
        manifest_digest = _manifest_digest(manifest)
        slices = [
            data[offset : offset + max_chunk_bytes]
            for offset in range(0, length, max_chunk_bytes)
        ] or [b""]
        chunks = [
            self._dump_payload(
                {
                    "d": base64_encode(piece).decode("ascii"),
                    "i": index,
                    "m": manifest_digest,
                }
            )
            for index, piece in enumerate(slices)
        ]

        if previous_count is not None and previous_count > count:
            stale_indices = list(range(count, previous_count))
        else:
            stale_indices = []

        return ChunkedMessage(
            manifest=manifest,
            chunks=chunks,
            message_id=message_id,
            count=count,
            length=length,
            digest=digest,
            stale_indices=stale_indices,
        )

    def join(
        self,
        manifest: str | bytes,
        chunks: t.Iterable[str | bytes],
        max_total_bytes: int | None = None,
    ) -> ReassemblyResult:
        """Reassemble a token from its ``manifest`` and ``chunks``. The
        chunks may be given in any order. The token is only returned
        once every chunk is present and the whole payload verifies
        against the manifest.

        Duplicate identical chunks are ignored. Distinct error types
        are raised for other abnormal input:

        -   :class:`ForeignChunkError` if a chunk belongs to a
            different manifest, preventing chunks from two issuances
            being mixed.
        -   :class:`ExtraChunkError` if a chunk's position is outside
            the declared range.
        -   :class:`ConflictingChunkError` if two different chunks
            claim the same position.
        -   :class:`ChunkBudgetError` if the declared total length
            exceeds ``max_total_bytes``.
        -   :class:`~itsdangerous.exc.BadSignature` if a signature does
            not verify.

        :param manifest: The signed manifest produced by :meth:`split`.
        :param chunks: The signed chunks, in any order.
        :param max_total_bytes: Maximum allowed total token length.
        """
        manifest_payload = self._load_payload(manifest)

        try:
            count = int(manifest_payload["count"])
            length = int(manifest_payload["length"])
            digest = str(manifest_payload["digest"])
        except (KeyError, TypeError, ValueError) as e:
            raise ChunkError("Manifest is missing required fields.") from e

        if count < 1 or length < 0:
            raise ChunkError("Manifest declares an invalid count or length.")

        if max_total_bytes is not None and length > max_total_bytes:
            raise ChunkBudgetError(
                f"Manifest declares {length} bytes, over the budget of"
                f" {max_total_bytes} bytes."
            )

        manifest_digest = _manifest_digest(want_bytes(manifest).decode("utf-8"))
        received: dict[int, bytes] = {}

        for chunk in chunks:
            payload = self._load_payload(chunk)

            if payload.get("m") != manifest_digest:
                raise ForeignChunkError(
                    "Chunk belongs to a different manifest and cannot be"
                    " mixed into this message."
                )

            index = payload.get("i")

            if (
                not isinstance(index, int)
                or isinstance(index, bool)
                or not 0 <= index < count
            ):
                raise ExtraChunkError(
                    f"Chunk position {index!r} is outside the declared range"
                    f" of {count} chunks."
                )

            try:
                piece = base64_decode(str(payload["d"]))
            except (KeyError, BadData) as e:
                raise ChunkError("Chunk payload is invalid.") from e

            if index in received:
                if received[index] != piece:
                    raise ConflictingChunkError(
                        f"Two different chunks claim position {index}."
                    )

                continue

            received[index] = piece

        missing = [index for index in range(count) if index not in received]

        if missing:
            return ReassemblyResult(
                complete=False,
                token=None,
                missing=missing,
                received=sorted(received),
            )

        token = b"".join(received[index] for index in range(count))

        if len(token) != length or hashlib.sha256(token).hexdigest() != digest:
            raise ChunkError("Reassembled data does not match the manifest.")

        return ReassemblyResult(
            complete=True,
            token=token,
            missing=[],
            received=sorted(received),
        )

    def _dump_payload(self, payload: dict[str, t.Any]) -> str:
        """Serialize and sign a manifest or chunk payload."""
        data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        return self._signer.sign(base64_encode(data)).decode("utf-8")

    def _load_payload(self, signed: str | bytes) -> dict[str, t.Any]:
        """Verify and deserialize a manifest or chunk payload. Raises
        :class:`~itsdangerous.exc.BadSignature` if the signature does
        not verify.
        """
        data = base64_decode(self._signer.unsign(want_bytes(signed)))

        try:
            payload = json.loads(data)
        except json.JSONDecodeError as e:
            raise ChunkError("Signed payload is not valid JSON.") from e

        if not isinstance(payload, dict):
            raise ChunkError("Signed payload is not an object.")

        return t.cast("dict[str, t.Any]", payload)


def _manifest_digest(manifest: str) -> str:
    """Digest of the signed manifest, binding chunks to exactly one
    issuance.
    """
    return hashlib.sha256(manifest.encode("utf-8")).hexdigest()
