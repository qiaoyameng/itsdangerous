import pytest

from itsdangerous.chunked import ChunkedSerializer
from itsdangerous.exc import BadChunkBinding
from itsdangerous.exc import BadSignature
from itsdangerous.exc import ChunkTooLarge
from itsdangerous.exc import DuplicateChunk
from itsdangerous.exc import ExtraChunks
from itsdangerous.exc import MissingChunks


@pytest.fixture()
def serializer() -> ChunkedSerializer:
    return ChunkedSerializer("secret-key")


@pytest.fixture()
def short_token() -> bytes:
    return b"state-token:" + b"A" * 48


@pytest.fixture()
def long_token() -> bytes:
    return b"state-token:" + b"B" * 108


@pytest.fixture()
def short(serializer: ChunkedSerializer, short_token: bytes):
    return serializer.dumps(
        short_token, 160, message_id=b"session-1", previous_chunk_count=5
    )


@pytest.fixture()
def long(serializer: ChunkedSerializer, long_token: bytes):
    return serializer.dumps(long_token, 160, message_id=b"session-1")


def test_dumps_binds_manifest_and_respects_budget(
    serializer: ChunkedSerializer,
    short: object,
    long: object,
    short_token: bytes,
    long_token: bytes,
) -> None:
    assert len(short.chunks) == 2
    assert len(long.chunks) == 4
    assert all(len(chunk) <= 160 for chunk in short.chunks)
    assert all(len(chunk) <= 160 for chunk in long.chunks)
    assert short.delete_indices == (2, 3, 4)

    assert serializer.loads(short.manifest, dict(enumerate(short.chunks))).token == (
        short_token
    )
    assert serializer.loads(long.manifest, dict(enumerate(long.chunks))).token == (
        long_token
    )


def test_loads_accepts_reversed_order_and_duplicate_matching_chunks(
    serializer: ChunkedSerializer, long: object, long_token: bytes
) -> None:
    chunks = [
        (3, long.chunks[3]),
        (1, long.chunks[1]),
        (0, long.chunks[0]),
        (2, long.chunks[2]),
        (1, long.chunks[1]),
    ]

    assert serializer.loads(long.manifest, chunks).token == long_token


def test_similar_tokens_with_different_lengths_cannot_be_mixed(
    serializer: ChunkedSerializer, short: object, long: object
) -> None:
    mixed = {
        0: short.chunks[0],
        1: short.chunks[1],
        2: long.chunks[2],
        3: long.chunks[3],
    }

    with pytest.raises(BadChunkBinding):
        serializer.loads(long.manifest, mixed)

    with pytest.raises(ExtraChunks) as exc_info:
        serializer.loads(
            short.manifest,
            {
                0: long.chunks[0],
                1: long.chunks[1],
                3: long.chunks[3],
            },
        )

    assert exc_info.value.indices == (3,)


def test_conflicting_duplicate_chunk(
    serializer: ChunkedSerializer, long: object
) -> None:
    chunks = dict(enumerate(long.chunks))

    with pytest.raises(DuplicateChunk) as exc_info:
        serializer.loads(long.manifest, [*chunks.items(), (2, long.chunks[1])])

    assert exc_info.value.index == 2


def test_missing_chunk(serializer: ChunkedSerializer, long: object) -> None:
    chunks = dict(enumerate(long.chunks))
    del chunks[2]

    with pytest.raises(MissingChunks) as exc_info:
        serializer.loads(long.manifest, chunks)

    assert exc_info.value.indices == (2,)


def test_extra_chunk(serializer: ChunkedSerializer, long: object) -> None:
    chunks = dict(enumerate(long.chunks))
    chunks[4] = long.chunks[0]

    with pytest.raises(ExtraChunks) as exc_info:
        serializer.loads(long.manifest, chunks)

    assert exc_info.value.indices == (4,)


def test_chunk_over_budget(serializer: ChunkedSerializer, long: object) -> None:
    chunks = dict(enumerate(long.chunks))
    chunks[0] += "x"

    with pytest.raises(ChunkTooLarge) as exc_info:
        serializer.loads(long.manifest, chunks)

    assert exc_info.value.indices == (0,)


def test_tampered_manifest_and_chunk_are_rejected(
    serializer: ChunkedSerializer, long: object
) -> None:
    with pytest.raises(BadSignature):
        serializer.loads(long.manifest[:-1], dict(enumerate(long.chunks)))

    chunks = dict(enumerate(long.chunks))
    chunks[1] = chunks[1][:-2] + ("A" if chunks[1][-2] != "A" else "B")

    with pytest.raises(BadChunkBinding):
        serializer.loads(long.manifest, chunks)


def test_cleanup_plan_for_shorter_reissue(
    serializer: ChunkedSerializer, short: object, short_token: bytes, long: object
) -> None:
    reissued = serializer.dumps(
        short_token,
        160,
        message_id=b"session-1",
        previous_chunk_count=len(long.chunks),
    )

    assert reissued.delete_indices == (2, 3)
    assert (
        serializer.loads(
            reissued.manifest,
            dict(enumerate(reissued.chunks)),
            previous_chunk_count=len(long.chunks),
        ).delete_indices
        == (2, 3)
    )


def test_message_id_can_be_random_or_deterministic(
    serializer: ChunkedSerializer, long_token: bytes
) -> None:
    first = serializer.dumps(long_token, 160)
    second = serializer.dumps(long_token, 160)

    assert first.manifest != second.manifest
    assert serializer.loads(first.manifest, dict(enumerate(first.chunks))).token == (
        long_token
    )

    deterministic = serializer.dumps(
        long_token, 160, message_id=b"deterministic-id"
    )
    deterministic_again = serializer.dumps(
        long_token, 160, message_id=b"deterministic-id"
    )

    assert deterministic.manifest == deterministic_again.manifest
    assert deterministic.chunks == deterministic_again.chunks
