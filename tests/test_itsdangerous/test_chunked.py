import hashlib

import pytest

from itsdangerous.chunked import ChunkBudgetError
from itsdangerous.chunked import ConflictingChunkError
from itsdangerous.chunked import ExtraChunkError
from itsdangerous.chunked import ForeignChunkError
from itsdangerous.chunked import TokenChunker
from itsdangerous.exc import BadSignature

# Two tokens with nearly identical content but different lengths.
TOKEN_SHORT = '{"sid": "abc123", "user": "alice", "roles": ["reader"]}'
TOKEN_LONG = (
    '{"sid": "abc123", "user": "alice", "roles": ["reader", "writer", "admin"],'
    ' "scopes": ["files:read", "files:write", "users:read", "billing:read"]}'
)


@pytest.fixture()
def chunker() -> TokenChunker:
    return TokenChunker("secret-key")


@pytest.fixture()
def short_message(chunker: TokenChunker):
    return chunker.split(TOKEN_SHORT, max_chunk_bytes=16)


@pytest.fixture()
def long_message(chunker: TokenChunker):
    return chunker.split(TOKEN_LONG, max_chunk_bytes=16)


class TestSplit:
    def test_roundtrip(self, chunker: TokenChunker, long_message):
        result = chunker.join(long_message.manifest, long_message.chunks)
        assert result.complete
        assert result.token == TOKEN_LONG.encode()
        assert result.missing == []
        assert result.received == list(range(long_message.count))

    def test_out_of_order(self, chunker: TokenChunker, long_message):
        shuffled = list(reversed(long_message.chunks))
        result = chunker.join(long_message.manifest, shuffled)
        assert result.complete
        assert result.token == TOKEN_LONG.encode()

    def test_random_message_id(self, chunker: TokenChunker):
        first = chunker.split(TOKEN_SHORT, max_chunk_bytes=16)
        second = chunker.split(TOKEN_SHORT, max_chunk_bytes=16)
        assert first.message_id != second.message_id
        assert first.manifest != second.manifest

    def test_deterministic_message_id(self, chunker: TokenChunker):
        first = chunker.split(TOKEN_SHORT, 16, message_id="msg-1")
        second = chunker.split(TOKEN_SHORT, 16, message_id="msg-1")
        assert first.manifest == second.manifest
        assert first.chunks == second.chunks

    def test_manifest_binds_metadata(self, chunker: TokenChunker, long_message):
        assert long_message.count == len(long_message.chunks)
        assert long_message.length == len(TOKEN_LONG.encode())
        assert long_message.digest == hashlib.sha256(
            TOKEN_LONG.encode()
        ).hexdigest()

    def test_invalid_chunk_size(self, chunker: TokenChunker):
        with pytest.raises(ValueError):
            chunker.split(TOKEN_SHORT, max_chunk_bytes=0)

    def test_stale_indices_cleanup_plan(self, chunker: TokenChunker):
        long_message = chunker.split(TOKEN_LONG, max_chunk_bytes=16)
        assert long_message.stale_indices == []

        short_message = chunker.split(
            TOKEN_SHORT, max_chunk_bytes=16, previous_count=long_message.count
        )
        assert short_message.count < long_message.count
        assert short_message.stale_indices == list(
            range(short_message.count, long_message.count)
        )

    def test_stale_indices_empty_when_growing(self, chunker: TokenChunker):
        short_message = chunker.split(TOKEN_SHORT, max_chunk_bytes=16)
        long_message = chunker.split(
            TOKEN_LONG, max_chunk_bytes=16, previous_count=short_message.count
        )
        assert long_message.stale_indices == []


class TestJoin:
    def test_cannot_mix_issuances(
        self, chunker: TokenChunker, short_message, long_message
    ):
        mixed = [short_message.chunks[0], *long_message.chunks[1:]]

        with pytest.raises(ForeignChunkError):
            chunker.join(long_message.manifest, mixed)

    def test_cannot_mix_deterministic_ids(self, chunker: TokenChunker):
        short_message = chunker.split(TOKEN_SHORT, 16, message_id="same-id")
        long_message = chunker.split(TOKEN_LONG, 16, message_id="same-id")
        mixed = [short_message.chunks[0], *long_message.chunks[1:]]

        with pytest.raises(ForeignChunkError):
            chunker.join(long_message.manifest, mixed)

    def test_duplicate_identical_chunk_is_idempotent(
        self, chunker: TokenChunker, long_message
    ):
        chunks = [*long_message.chunks, long_message.chunks[0]]
        result = chunker.join(long_message.manifest, chunks)
        assert result.complete
        assert result.token == TOKEN_LONG.encode()

    def test_conflicting_duplicate(self, chunker: TokenChunker, long_message):
        forged = chunker._dump_payload(
            {"d": "b3RoZXItZGF0YQ", "i": 0, "m": _digest(long_message.manifest)}
        )

        with pytest.raises(ConflictingChunkError):
            chunker.join(long_message.manifest, [*long_message.chunks, forged])

    def test_missing_chunk(self, chunker: TokenChunker, long_message):
        chunks = long_message.chunks[:2]
        result = chunker.join(long_message.manifest, chunks)
        assert not result.complete
        assert result.token is None
        assert result.missing == list(range(2, long_message.count))
        assert result.received == [0, 1]

    def test_extra_chunk(self, chunker: TokenChunker, long_message):
        forged = chunker._dump_payload(
            {
                "d": "eA",
                "i": long_message.count,
                "m": _digest(long_message.manifest),
            }
        )

        with pytest.raises(ExtraChunkError):
            chunker.join(long_message.manifest, [*long_message.chunks, forged])

    def test_budget_exceeded(self, chunker: TokenChunker, long_message):
        with pytest.raises(ChunkBudgetError):
            chunker.join(
                long_message.manifest,
                long_message.chunks,
                max_total_bytes=long_message.length - 1,
            )

    def test_budget_ok(self, chunker: TokenChunker, long_message):
        result = chunker.join(
            long_message.manifest,
            long_message.chunks,
            max_total_bytes=long_message.length,
        )
        assert result.complete

    def test_tampered_manifest(self, chunker: TokenChunker, long_message):
        tampered = long_message.manifest[:-2] + "xx"

        with pytest.raises(BadSignature):
            chunker.join(tampered, long_message.chunks)

    def test_tampered_chunk(self, chunker: TokenChunker, long_message):
        chunks = list(long_message.chunks)
        chunks[0] = chunks[0][:-2] + "xx"

        with pytest.raises(BadSignature):
            chunker.join(long_message.manifest, chunks)

    def test_wrong_key(self, long_message):
        other = TokenChunker("other-key")

        with pytest.raises(BadSignature):
            other.join(long_message.manifest, long_message.chunks)


def _digest(manifest: str) -> str:
    return hashlib.sha256(manifest.encode("utf-8")).hexdigest()
