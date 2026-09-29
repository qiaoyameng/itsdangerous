import hashlib
import tracemalloc
from functools import partial

import pytest

from itsdangerous.exc import BadSignature
from itsdangerous.signer import Signer
from itsdangerous.stream import StreamSigner


def _chunked(data, size):
    return [data[i : i + size] for i in range(0, len(data), size)]


class TestStreamSigner:
    @pytest.fixture()
    def signer_factory(self):
        return partial(StreamSigner, secret_key="secret-key", purpose="upload")

    @pytest.fixture()
    def signer(self, signer_factory):
        return signer_factory()

    def test_roundtrip(self, signer):
        data = b"streamed payload" * 100
        sig = signer.sign_stream(_chunked(data, 7))
        assert isinstance(sig, bytes)
        assert data not in sig  # detached: signature does not embed data
        assert signer.validate_stream(_chunked(data, 1024), sig)
        signer.verify_stream(iter([data]), sig)  # does not raise

    def test_accepts_one_shot_generator(self, signer):
        data = b"abc" * 1000
        sig = signer.sign_stream(iter([data]))
        assert signer.validate_stream((c for c in _chunked(data, 13)), sig)

    def test_empty_stream(self, signer):
        sig = signer.sign_stream([])
        assert signer.validate_stream([], sig)
        assert signer.validate_stream(iter([]), sig)
        # The empty stream is distinct from any non-empty stream.
        assert not signer.validate_stream([b"x"], sig)
        other = signer.sign_stream([b"x"])
        assert not signer.validate_stream([], other)

    def test_empty_chunks_ignored(self, signer):
        assert signer.sign_stream([b"", b"ab", b"", b"cd", b""]) == (
            signer.sign_stream([b"abcd"])
        )

    def test_chunking_does_not_affect_signature(self, signer):
        data = bytes(range(256)) * 10
        expected = signer.sign_stream([data])

        for size in (1, 3, 7, 64, 4096, len(data)):
            assert signer.sign_stream(_chunked(data, size)) == expected

    def test_str_chunks_encoded(self, signer):
        assert signer.sign_stream(["héllo"]) == signer.sign_stream(["héllo".encode()])

    def test_invalid_chunk_type(self, signer):
        with pytest.raises(TypeError):
            signer.sign_stream([b"ok", 42])

        verifier = signer.new_verifier()

        with pytest.raises(TypeError):
            verifier.update(None)

    def test_truncated_stream_rejected(self, signer):
        data = b"important data" * 100
        sig = signer.sign_stream([data])

        for cut in (0, 1, len(data) // 2, len(data) - 1):
            assert not signer.validate_stream([data[:cut]], sig)

        with pytest.raises(BadSignature):
            signer.verify_stream([data[:-1]], sig)

    def test_appended_bytes_rejected(self, signer):
        data = b"important data" * 100
        sig = signer.sign_stream([data])
        assert not signer.validate_stream([data + b"x"], sig)
        assert not signer.validate_stream([data, b"extra"], sig)

    def test_modified_byte_rejected(self, signer):
        data = bytearray(b"a" * 1000)
        sig = signer.sign_stream([bytes(data)])
        data[500] = ord("b")
        assert not signer.validate_stream([bytes(data)], sig)

    def test_purpose_is_bound(self, signer_factory):
        data = b"same payload"
        sig = signer_factory(purpose="avatar").sign_stream([data])
        assert not signer_factory(purpose="document").validate_stream([data], sig)
        assert signer_factory(purpose="avatar").validate_stream([data], sig)

    def test_purpose_required(self):
        with pytest.raises(TypeError):
            StreamSigner("secret-key")  # pyright: ignore

    @pytest.mark.parametrize("digest", [hashlib.sha1, hashlib.sha256])
    def test_not_cross_compatible_with_signer(self, digest):
        # Even with the same secret, salt, and digest method, a plain
        # Signer signature must not be accepted as a stream signature,
        # and vice versa.
        salt = "shared-salt"
        plain = Signer("secret-key", salt=salt, digest_method=digest)
        stream = StreamSigner(
            "secret-key", purpose="upload", salt=salt, digest_method=digest
        )
        data = b"payload"

        plain_sig = plain.sign(data).rsplit(b".", 1)[1]
        assert not stream.validate_stream([data], plain_sig)

        stream_sig = stream.sign_stream([data])
        assert not plain.verify_signature(data, stream_sig)

    def test_different_default_salt_from_signer(self):
        assert StreamSigner("k", purpose="p").salt != Signer("k").salt

    def test_key_rotation(self):
        old = StreamSigner("old-key", purpose="upload")
        rotated = StreamSigner(["old-key", "new-key"], purpose="upload")
        data = b"payload"

        # Signs with the newest key.
        sig = rotated.sign_stream([data])
        assert rotated.validate_stream([data], sig)
        assert not old.validate_stream([data], sig)

        # Still verifies signatures made with the old key.
        old_sig = old.sign_stream([data])
        assert rotated.validate_stream([data], old_sig)

    def test_bad_base64_signature(self, signer):
        with pytest.raises(BadSignature):
            signer.verify_stream([b"data"], b"!!!")

        assert not signer.validate_stream([b"data"], b"!!!")

    def test_upstream_error_during_sign(self, signer):
        def broken():
            yield b"partial"
            raise RuntimeError("upstream read failed")

        with pytest.raises(RuntimeError, match="upstream read failed"):
            signer.sign_stream(broken())

    def test_upstream_error_during_verify(self, signer):
        sig = signer.sign_stream([b"partial"])

        def broken():
            yield b"partial"
            raise RuntimeError("upstream read failed")

        with pytest.raises(RuntimeError, match="upstream read failed"):
            signer.verify_stream(broken(), sig)

    def test_incremental_verifier(self, signer):
        data = b"incremental" * 50
        sig = signer.sign_stream([data])
        verifier = signer.new_verifier()

        for chunk in _chunked(data, 11):
            verifier.update(chunk)

        assert verifier.length == len(data)
        verifier.verify(sig)

    def test_incremental_verifier_mismatch(self, signer):
        sig = signer.sign_stream([b"expected"])
        verifier = signer.new_verifier()
        verifier.update(b"expecte")

        with pytest.raises(BadSignature):
            verifier.verify(sig)

    def test_no_success_before_eof(self, signer):
        # Feeding chunks never produces a success signal; only
        # verify() at EOF can confirm, and it finalizes the verifier.
        sig = signer.sign_stream([b"data"])
        verifier = signer.new_verifier()
        verifier.update(b"data")
        verifier.verify(sig)

        with pytest.raises(RuntimeError):
            verifier.update(b"more")

    def test_iter_verified(self, signer):
        data = b"verify while streaming" * 10
        sig = signer.sign_stream([data])
        out = b"".join(signer.iter_verified(_chunked(data, 9), sig))
        assert out == data

    def test_iter_verified_raises_at_eof(self, signer):
        data = b"verify while streaming"
        sig = signer.sign_stream([data])
        tampered = [data[:-1] + b"X"]
        gen = signer.iter_verified(tampered, sig)
        collected = []

        # Chunks are delivered before the failure is detected at EOF.
        with pytest.raises(BadSignature):
            for chunk in gen:
                collected.append(chunk)

        assert b"".join(collected) == tampered[0]

    def test_iter_verified_upstream_error(self, signer):
        sig = signer.sign_stream([b"partial"])

        def broken():
            yield b"partial"
            raise RuntimeError("upstream read failed")

        with pytest.raises(RuntimeError, match="upstream read failed"):
            list(signer.iter_verified(broken(), sig))

    def test_safe_consumption_two_pass(self, signer, tmp_path):
        # A re-readable source can be verified first, then consumed.
        # Unverified data is never processed.
        path = tmp_path / "big.bin"
        data = b"file contents" * 1000
        path.write_bytes(data)
        sig = signer.sign_stream([data])

        processed = []

        def consume():
            with path.open("rb") as f:
                while chunk := f.read(4096):
                    processed.append(chunk)

        with path.open("rb") as f:
            signer.verify_stream(iter(lambda: f.read(4096), b""), sig)

        consume()
        assert b"".join(processed) == data

        # Tampered file: verification fails before any consumption.
        path.write_bytes(data + b"extra")
        processed.clear()

        with pytest.raises(BadSignature), path.open("rb") as f:
            signer.verify_stream(iter(lambda: f.read(4096), b""), sig)

        assert processed == []

    def test_safe_consumption_quarantine(self, signer, tmp_path):
        # A one-shot source is staged unverified and only committed
        # after iter_verified completes without raising.
        final = tmp_path / "out.bin"
        data = b"one shot" * 100
        sig = signer.sign_stream([data])

        def ingest(chunks, signature):
            staging = tmp_path / "out.bin.partial"

            with staging.open("wb") as f:
                for chunk in signer.iter_verified(chunks, signature):
                    f.write(chunk)

            staging.replace(final)  # only reached if verified

        ingest(_chunked(data, 100), sig)
        assert final.read_bytes() == data

        final.unlink()
        with pytest.raises(BadSignature):
            ingest(_chunked(data + b"extra", 100), sig)

        assert not final.exists()


class TestStreamMemory:
    @staticmethod
    def _chunks(count, size=65536):
        for _ in range(count):
            # A distinct allocation per chunk, so retaining chunks
            # would show up as memory growth.
            yield bytes(size)

    @staticmethod
    def _peak(func, *args):
        tracemalloc.start()

        try:
            func(*args)
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    def test_sign_memory_constant(self):
        signer = StreamSigner("secret-key", purpose="big-file")
        small = self._peak(signer.sign_stream, self._chunks(16))  # 1 MiB
        large = self._peak(signer.sign_stream, self._chunks(2048))  # 128 MiB
        assert large < 4 * 1024 * 1024
        assert large - small < 1024 * 1024

    def test_verify_memory_constant(self):
        signer = StreamSigner("secret-key", purpose="big-file")
        small_sig = signer.sign_stream(self._chunks(16))
        large_sig = signer.sign_stream(self._chunks(2048))
        small = self._peak(signer.verify_stream, self._chunks(16), small_sig)
        large = self._peak(signer.verify_stream, self._chunks(2048), large_sig)
        assert large < 4 * 1024 * 1024
        assert large - small < 1024 * 1024
