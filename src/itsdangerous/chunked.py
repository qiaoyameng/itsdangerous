from __future__ import annotations

import collections.abc as cabc
import hashlib
import os
import struct
import typing as t
from dataclasses import dataclass

from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import want_bytes
from .exc import BadChunkBinding
from .exc import BadChunkDigest
from .exc import BadData
from .exc import BadPayload
from .exc import BadSignature
from .exc import ChunkTooLarge
from .exc import DuplicateChunk
from .exc import ExtraChunks
from .exc import MissingChunks
from .signer import Signer

_MANIFEST_VERSION = 1
_MANIFEST_STRUCT = struct.Struct(">BBIQI")
_CHUNK_STRUCT = struct.Struct(">BII")


@dataclass(frozen=True)
class ChunkedToken:
    """A signed manifest and the indexed, signed token chunks."""

    manifest: str
    chunks: tuple[str, ...]
    delete_indices: tuple[int, ...]


@dataclass(frozen=True)
class ReassembledToken:
    """The verified token and stale chunk indices to remove."""

    token: bytes
    delete_indices: tuple[int, ...] = ()


class ChunkedSerializer:
    """Split and reassemble opaque tokens without HTTP framework support."""

    def __init__(
        self,
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        *,
        salt: str | bytes | None = b"itsdangerous.ChunkedSerializer",
        signer: type[Signer] = Signer,
        signer_kwargs: dict[str, t.Any] | None = None,
        digest_method: t.Any = hashlib.sha256,
    ):
        salt_value = (
            b"itsdangerous.ChunkedSerializer"
            if salt is None
            else want_bytes(salt)
        )
        signer_config = dict(signer_kwargs or {})

        if "digest_method" not in signer_config and "algorithm" not in signer_config:
            signer_config["digest_method"] = digest_method

        self.manifest_signer = signer(
            secret_key, salt=salt_value + b".manifest", **signer_config
        )
        self.chunk_signer = signer(
            secret_key, salt=salt_value + b".chunk", **signer_config
        )

    def dumps(
        self,
        token: str | bytes,
        max_chunk_bytes: int,
        *,
        message_id: str | bytes | None = None,
        previous_chunk_count: int | None = None,
    ) -> ChunkedToken:
        """Sign and split ``token`` into fields no larger than the byte budget."""
        if isinstance(max_chunk_bytes, bool) or not isinstance(max_chunk_bytes, int):
            raise TypeError("'max_chunk_bytes' must be an integer.")

        if max_chunk_bytes <= 0:
            raise ValueError("'max_chunk_bytes' must be positive.")

        if max_chunk_bytes > 0xFFFFFFFF:
            raise ValueError("'max_chunk_bytes' is too large.")

        raw_token = want_bytes(token)

        if message_id is None:
            raw_message_id = os.urandom(16)
        else:
            raw_message_id = want_bytes(message_id)

        if not 0 < len(raw_message_id) < 256:
            raise ValueError("'message_id' must be between 1 and 255 bytes.")

        signed_overhead = len(self.chunk_signer.sign(b""))
        chunk_overhead = _CHUNK_STRUCT.size + 32 + signed_overhead
        capacity = 3 * (max_chunk_bytes // 4) - chunk_overhead

        if capacity < 0 or (raw_token and capacity == 0):
            raise ValueError(
                "'max_chunk_bytes' is too small to contain a signed chunk."
            )

        _validate_previous_chunk_count(previous_chunk_count)

        chunk_count = (
            1
            if not raw_token
            else (len(raw_token) + capacity - 1) // capacity
        )

        if chunk_count > 0xFFFFFFFF:
            raise ValueError("Token produces too many chunks.")

        digest = hashlib.sha256(raw_token).digest()
        manifest_payload = _MANIFEST_STRUCT.pack(
            _MANIFEST_VERSION,
            len(raw_message_id),
            chunk_count,
            len(raw_token),
            max_chunk_bytes,
        ) + raw_message_id + digest
        manifest = base64_encode(
            self.manifest_signer.sign(manifest_payload)
        ).decode("ascii")

        if len(manifest) > max_chunk_bytes:
            raise ValueError(
                "'max_chunk_bytes' is too small to contain the signed manifest."
            )

        manifest_ref = hashlib.sha256(want_bytes(manifest)).digest()
        chunks = []

        for index in range(chunk_count):
            data = raw_token[index * capacity : (index + 1) * capacity]
            chunk_payload = (
                _CHUNK_STRUCT.pack(len(manifest_ref), index, len(data))
                + manifest_ref
                + data
            )
            signed_chunk = base64_encode(self.chunk_signer.sign(chunk_payload))
            chunks.append(signed_chunk.decode("ascii"))

        delete_indices = _stale_indices(chunk_count, previous_chunk_count)
        return ChunkedToken(manifest, tuple(chunks), delete_indices)

    def loads(
        self,
        manifest: str | bytes,
        chunks: cabc.Mapping[int, str | bytes] | cabc.Iterable[tuple[int, str | bytes]],
        *,
        previous_chunk_count: int | None = None,
    ) -> ReassembledToken:
        """Verify all fields before concatenating and returning the token."""
        raw_manifest = want_bytes(manifest, encoding="ascii", errors="strict")

        try:
            signed_manifest = base64_decode(raw_manifest)
            manifest_payload = self.manifest_signer.unsign(signed_manifest)
            version, id_length, chunk_count, total_length, max_chunk_bytes = (
                _MANIFEST_STRUCT.unpack_from(manifest_payload)
            )
            fixed_size = _MANIFEST_STRUCT.size
            message_id = manifest_payload[fixed_size : fixed_size + id_length]
            digest = manifest_payload[
                fixed_size + id_length : fixed_size + id_length + 32
            ]
            valid_manifest = (
                version == _MANIFEST_VERSION
                and 0 < id_length < 256
                and len(message_id) == id_length
                and chunk_count > 0
                and max_chunk_bytes > 0
                and len(raw_manifest) <= max_chunk_bytes
                and len(digest) == 32
                and len(manifest_payload) == fixed_size + id_length + 32
            )
        except (BadSignature, BadData, struct.error) as e:
            raise BadSignature("Manifest signature is invalid.") from e

        if not valid_manifest:
            raise BadPayload("Manifest payload is malformed.")

        _validate_previous_chunk_count(previous_chunk_count)
        entries = _chunk_entries(chunks)
        indexed_chunks: dict[int, str | bytes] = {}
        extra_indices = set()

        for index, value in entries:
            if index >= chunk_count:
                extra_indices.add(index)
            elif index in indexed_chunks:
                if want_bytes(indexed_chunks[index]) != want_bytes(value):
                    raise DuplicateChunk(index)
            else:
                indexed_chunks[index] = value

        if extra_indices:
            raise ExtraChunks(sorted(extra_indices))

        missing_indices = [
            index for index in range(chunk_count) if index not in indexed_chunks
        ]

        if missing_indices:
            raise MissingChunks(missing_indices)

        oversized_indices = [
            index
            for index, value in indexed_chunks.items()
            if len(want_bytes(value)) > max_chunk_bytes
        ]

        if oversized_indices:
            raise ChunkTooLarge(oversized_indices)

        manifest_ref = hashlib.sha256(raw_manifest).digest()
        verified_data = []

        for index in range(chunk_count):
            try:
                signed_chunk = base64_decode(want_bytes(indexed_chunks[index]))
                chunk_payload = self.chunk_signer.unsign(signed_chunk)
                ref_length, chunk_index, data_length = _CHUNK_STRUCT.unpack_from(
                    chunk_payload
                )
                ref_start = _CHUNK_STRUCT.size
                ref_end = ref_start + ref_length
                data_end = ref_end + data_length
                ref = chunk_payload[ref_start:ref_end]
                data = chunk_payload[ref_end:data_end]
                valid_chunk = len(chunk_payload) == data_end
            except (BadSignature, BadData, struct.error) as e:
                raise BadChunkBinding(f"Chunk {index} signature is invalid.") from e

            if not valid_chunk or ref != manifest_ref or chunk_index != index:
                raise BadChunkBinding(
                    f"Chunk {index} is not bound to this manifest position."
                )

            verified_data.append(data)

        reassembled = b"".join(verified_data)
        if len(reassembled) != total_length or hashlib.sha256(
            reassembled
        ).digest() != digest:
            raise BadChunkDigest("Reassembled token does not match its manifest.")

        delete_indices = _stale_indices(chunk_count, previous_chunk_count)
        return ReassembledToken(bytes(reassembled), delete_indices)


def _validate_previous_chunk_count(previous_chunk_count: int | None) -> None:
    if isinstance(previous_chunk_count, bool) or (
        previous_chunk_count is not None
        and not isinstance(previous_chunk_count, int)
    ):
        raise TypeError("'previous_chunk_count' must be an integer or None.")

    if previous_chunk_count is not None and previous_chunk_count < 0:
        raise ValueError("'previous_chunk_count' must not be negative.")


def _stale_indices(
    chunk_count: int, previous_chunk_count: int | None
) -> tuple[int, ...]:
    if previous_chunk_count is None:
        return ()

    return tuple(range(chunk_count, previous_chunk_count))


def _chunk_entries(
    chunks: cabc.Mapping[int, str | bytes] | cabc.Iterable[tuple[int, str | bytes]],
) -> list[tuple[int, str | bytes]]:
    if isinstance(chunks, cabc.Mapping):
        entries = list(chunks.items())
    else:
        try:
            entries = list(chunks)
        except TypeError as e:
            raise TypeError(
                "'chunks' must be a mapping or iterable of '(index, value)' pairs."
            ) from e

    normalized = []

    for entry in entries:
        try:
            index, value = entry
        except (TypeError, ValueError) as e:
            raise TypeError("Each chunk must be an '(index, value)' pair.") from e

        if isinstance(index, bool) or not isinstance(index, int):
            raise TypeError("Chunk indices must be integers.")

        if index < 0:
            raise ValueError("Chunk indices must not be negative.")

        if not isinstance(value, (str, bytes)):
            raise TypeError("Chunk values must be strings or bytes.")

        normalized.append((index, value))

    return normalized
