import tracemalloc
from functools import partial

import pytest

from itsdangerous.exc import BadSignature
from itsdangerous.signer import Signer
from itsdangerous.stream import StreamSigner


def _chunks(data, size):
    for i in range(0, len(data), size):
        yield data[i : i + size]


class TestStreamSigner:
    @pytest.fixture()
    def signer_factory(self):
        return partial(StreamSigner, secret_key="secret-key", purpose=b"test")

    @pytest.fixture()
    def signer(self, signer_factory):
        return signer_factory()

    def test_roundtrip(self, signer):
        sig = signer.sign_stream([b"hello", b" ", b"world"])
        assert isinstance(sig, bytes)
        signer.verify_stream(sig, [b"hello", b" ", b"world"])
        assert signer.validate_stream(sig, [b"hello", b" ", b"world"])

    def test_chunking_independent(self, signer):
        data = b"abcdefgh" * 100
        sig1 = signer.sign_stream([data])
        sig2 = signer.sign_stream(_chunks(data, 3))
        sig3 = signer.sign_stream(_chunks(data, 4096))
        assert sig1 == sig2 == sig3

    def test_empty_stream(self, signer):
        sig = signer.sign_stream(iter([]))
        signer.verify_stream(sig, [])
        assert signer.validate_stream(sig, iter([]))
        # An empty-stream signature must not validate non-empty data.
        assert not signer.validate_stream(sig, [b"x"])
        # A non-empty signature must not validate empty data.
        other = signer.sign_stream([b"x"])
        assert not signer.validate_stream(other, [])

    def test_accepts_one_shot_iterator(self, signer):
        sig = signer.sign_stream(iter([b"a", b"b"]))
        assert signer.validate_stream(sig, iter([b"a", b"b"]))

    def test_tampered_chunk(self, signer):
        sig = signer.sign_stream([b"hello", b"world"])

        with pytest.raises(BadSignature):
            signer.verify_stream(sig, [b"hello", b"w0rld"])

        assert not signer.validate_stream(sig, [b"hello", b"w0rld"])

    def test_truncated_stream(self, signer):
        chunks = [b"aaa", b"bbb", b"ccc"]
        sig = signer.sign_stream(chunks)

        with pytest.raises(BadSignature):
            signer.verify_stream(sig, chunks[:2])

        with pytest.raises(BadSignature):
            signer.verify_stream(sig, [b"aaa", b"bb"])

    def test_appended_bytes(self, signer):
        chunks = [b"aaa", b"bbb"]
        sig = signer.sign_stream(chunks)

        with pytest.raises(BadSignature):
            signer.verify_stream(sig, chunks + [b"x"])

    def test_wrong_purpose(self, signer_factory):
        signer = signer_factory()
        sig = signer.sign_stream([b"data"])
        other = signer_factory(purpose=b"other")
        assert not other.validate_stream(sig, [b"data"])

    def test_wrong_key(self, signer_factory):
        signer = signer_factory()
        sig = signer.sign_stream([b"data"])
        other = signer_factory(secret_key="other-key")
        assert not other.validate_stream(sig, [b"data"])

    def test_key_rotation(self, signer_factory):
        old = signer_factory(secret_key="old-key")
        sig = old.sign_stream([b"data"])
        rotated = signer_factory(secret_key=["old-key", "new-key"])
        assert rotated.validate_stream(sig, [b"data"])
        new_sig = rotated.sign_stream([b"data"])
        assert not old.validate_stream(new_sig, [b"data"])

    def test_not_accepted_by_plain_signer(self, signer):
        # A stream signature is detached and framed; a plain Signer must
        # not accept it even with the same secret and salt.
        sig = signer.sign_stream([b"data"])
        plain = Signer("secret-key", salt=signer.salt)
        assert not plain.validate(b"data" + plain.sep + sig)
        assert not plain.validate(sig)

    def test_plain_signer_signature_not_accepted(self, signer):
        # A signature from a plain Signer over the same bytes must not
        # validate as a stream signature, even with the derived salt.
        plain = Signer("secret-key", salt=signer.salt)
        signed = plain.sign(b"data")
        _, plain_sig = signed.rsplit(plain.sep, 1)
        assert not signer.validate_stream(plain_sig, [b"data"])

    def test_invalid_base64_signature(self, signer):
        with pytest.raises(BadSignature):
            signer.stream_verifier(b"!!!not-base64!!!")

        assert not signer.validate_stream(b"!!!", [b"data"])

    def test_upstream_error_sign(self, signer):
        def boom():
            yield b"partial"
            raise OSError("read failed")

        with pytest.raises(OSError):
            signer.sign_stream(boom())

    def test_upstream_error_verify(self, signer):
        sig = signer.sign_stream([b"aaa", b"bbb"])

        def boom():
            yield b"aaa"
            raise OSError("read failed")

        with pytest.raises(OSError):
            signer.verify_stream(sig, boom())

        with pytest.raises(OSError):
            signer.validate_stream(sig, boom())


class TestStreamVerifier:
    @pytest.fixture()
    def signer(self):
        return StreamSigner("secret-key", purpose=b"test")

    def test_incremental(self, signer):
        chunks = [b"he", b"llo", b" ", b"world"]
        sig = signer.sign_stream(chunks)
        verifier = signer.stream_verifier(sig)
        assert not verifier.verified

        for chunk in chunks:
            verifier.update(chunk)
            assert not verifier.verified

        assert verifier.length == 11
        verifier.verify()
        assert verifier.verified
        # verify is idempotent after success.
        verifier.verify()

    def test_update_after_verify(self, signer):
        sig = signer.sign_stream([b"a"])
        verifier = signer.stream_verifier(sig)
        verifier.update(b"a")
        verifier.verify()

        with pytest.raises(RuntimeError):
            verifier.update(b"b")

    def test_verify_failure(self, signer):
        sig = signer.sign_stream([b"a"])
        verifier = signer.stream_verifier(sig)
        verifier.update(b"b")

        with pytest.raises(BadSignature):
            verifier.verify()

        assert not verifier.verified

        with pytest.raises(BadSignature):
            verifier.verify()

    def test_verify_before_eof_fails(self, signer):
        # Calling verify before all chunks are fed must fail, since the
        # length so far cannot match the signed total length.
        sig = signer.sign_stream([b"aaa", b"bbb"])
        verifier = signer.stream_verifier(sig)
        verifier.update(b"aaa")

        with pytest.raises(BadSignature):
            verifier.verify()


class TestGuardStream:
    @pytest.fixture()
    def signer(self):
        return StreamSigner("secret-key", purpose=b"test")

    def test_yields_chunks_then_confirms(self, signer):
        chunks = [b"aaa", b"bbb", b"ccc"]
        sig = signer.sign_stream(chunks)
        out = list(signer.guard_stream(sig, iter(chunks)))
        assert out == chunks

    def test_raises_at_eof_on_tamper(self, signer):
        sig = signer.sign_stream([b"aaa", b"bbb"])
        guarded = signer.guard_stream(sig, iter([b"aaa", b"bbb", b"evil"]))
        assert next(guarded) == b"aaa"
        assert next(guarded) == b"bbb"
        # The extra chunk is still yielded as untrusted data; the
        # failure surfaces only when the stream ends.
        assert next(guarded) == b"evil"

        with pytest.raises(BadSignature):
            next(guarded)

    def test_upstream_error_propagates(self, signer):
        sig = signer.sign_stream([b"aaa"])

        def boom():
            yield b"aaa"
            raise OSError("read failed")

        guarded = signer.guard_stream(sig, boom())
        assert next(guarded) == b"aaa"

        with pytest.raises(OSError):
            next(guarded)


class TestConstantMemory:
    total = 32 * 1024 * 1024
    chunk_size = 64 * 1024
    # Peak Python allocation must stay far below the streamed size.
    max_peak = 4 * 1024 * 1024

    @pytest.fixture()
    def signer(self):
        return StreamSigner("secret-key", purpose=b"test")

    @staticmethod
    def _source(total, chunk_size):
        for _ in range(total // chunk_size):
            yield b"x" * chunk_size

    def _peak(self, func):
        tracemalloc.start()
        try:
            func()
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    def test_sign_memory_bounded(self, signer):
        def run():
            signer.sign_stream(self._source(self.total, self.chunk_size))

        assert self._peak(run) < self.max_peak

    def test_verify_memory_bounded(self, signer):
        sig = signer.sign_stream(self._source(self.total, self.chunk_size))

        def run():
            signer.verify_stream(sig, self._source(self.total, self.chunk_size))

        assert self._peak(run) < self.max_peak

    def test_guard_memory_bounded(self, signer):
        sig = signer.sign_stream(self._source(self.total, self.chunk_size))

        def run():
            for _ in signer.guard_stream(sig, self._source(self.total, self.chunk_size)):
                pass

        assert self._peak(run) < self.max_peak

    def test_signature_size_constant(self, signer):
        small = signer.sign_stream([b"x"])
        large = signer.sign_stream(self._source(self.total, self.chunk_size))
        assert len(small) == len(large)
