from __future__ import annotations

import collections.abc as cabc
import hashlib
import hmac
import struct
import typing as t

from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import want_bytes
from .exc import BadSignature
from .signer import Signer

#: Domain separation prefix mixed into the stream signing key. This
#: ensures a signature produced by :class:`Signer` (or any other
#: protocol using the same secret and salt) can never be reinterpreted
#: as a valid stream signature, and vice versa.
_DOMAIN: bytes = b"itsdangerous-stream-v1"

_len_struct = struct.Struct(">Q")


def _pack_length(value: int) -> bytes:
    if value > 0xFFFFFFFFFFFFFFFF:
        raise OverflowError("stream length does not fit in 8 bytes")

    return _len_struct.pack(value)


def _check_chunk(chunk: t.Any) -> bytes | bytearray | memoryview:
    if isinstance(chunk, str):
        return chunk.encode()

    if isinstance(chunk, (bytes, bytearray, memoryview)):
        return chunk

    raise TypeError(
        "stream chunks must be bytes-like or str,"
        f" not {type(chunk).__name__!r}"
    )


class StreamSigner(Signer):
    """A signer that produces and verifies *detached* signatures for
    large payloads as a stream of chunks, without ever holding the
    whole payload in memory.

    Unlike :class:`Signer`, the signature is returned separately from
    the data and is bound to three things besides the secret key:

    -   A caller-provided ``purpose`` string, so signatures made for
        one use cannot be replayed in another context.
    -   The exact length of the payload, so truncated or extended
        streams are rejected.
    -   A domain separation prefix, so signatures from plain
        :class:`Signer` (or any other protocol) are never accepted
        here, even with the same secret key and salt.

    Memory usage is constant: only the current chunk and the hash
    state are kept, regardless of the total stream size.

    :param secret_key: The secret key to sign and verify with. Can be
        a list of keys, oldest to newest, to support key rotation.
    :param purpose: A string identifying what the signature is for,
        such as ``"avatar-upload"``. Required so that signatures are
        always bound to an explicit context.
    :param salt: Extra key to combine with ``secret_key`` to
        distinguish signatures in different contexts.
    :param key_derivation: How to derive the signing key from the
        secret key and salt, same as :class:`Signer`.
    :param digest_method: Hash function to use for the HMAC signature.
        Defaults to :func:`hashlib.sha256`.

    .. versionadded:: 2.3
    """

    #: The default digest method, :func:`hashlib.sha256`. Unlike
    #: :class:`Signer` this is a new API, so it does not need to keep
    #: the historical SHA-1 default.
    default_digest_method: t.Any = staticmethod(hashlib.sha256)

    def __init__(
        self,
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        *,
        purpose: str | bytes,
        salt: str | bytes | None = b"itsdangerous.StreamSigner",
        key_derivation: str | None = None,
        digest_method: t.Any | None = None,
    ):
        super().__init__(
            secret_key,
            salt=salt,
            key_derivation=key_derivation,
            digest_method=digest_method,
        )
        #: The purpose context the signature is bound to.
        self.purpose: bytes = want_bytes(purpose)

    def _derive_stream_key(self, secret_key: bytes | None = None) -> bytes:
        """Derive the key used for stream signatures. Mixing the
        domain prefix and purpose into the base derived key separates
        this protocol from plain :class:`Signer` signatures and from
        other purposes.
        """
        base_key = self.derive_key(secret_key)
        mac = hmac.new(base_key, digestmod=self.digest_method)
        mac.update(_DOMAIN)
        mac.update(_pack_length(len(self.purpose)))
        mac.update(self.purpose)
        return mac.digest()

    def _new_mac(self, secret_key: bytes | None = None) -> hmac.HMAC:
        return hmac.new(
            self._derive_stream_key(secret_key), digestmod=self.digest_method
        )

    def sign_stream(self, chunks: cabc.Iterable[bytes]) -> bytes:
        """Consume a one-shot iterable of bytes and return the
        detached signature for the streamed payload. The payload
        itself is never stored or returned; transport it separately.

        If the iterable raises partway through, the exception
        propagates and no signature is produced.

        :param chunks: An iterable of ``bytes`` (or ``str``, encoded
            as UTF-8). May be a generator that can only be consumed
            once. Empty chunks are allowed and ignored.
        """
        mac = self._new_mac()
        total = 0

        for chunk in chunks:
            checked = _check_chunk(chunk)
            mac.update(checked)
            total += len(checked)

        mac.update(_pack_length(total))
        return base64_encode(mac.digest())

    def new_verifier(self) -> StreamVerifier:
        """Create a :class:`StreamVerifier` that accepts the payload
        chunk by chunk. Success can only be determined by calling
        :meth:`StreamVerifier.verify` once the stream has reached EOF.
        """
        return StreamVerifier(self)

    def verify_stream(self, chunks: cabc.Iterable[bytes], signature: bytes) -> None:
        """Consume a one-shot iterable of bytes and verify it against
        the detached ``signature``. Raises :class:`BadSignature` if
        the stream does not match, including if it was truncated or
        extended. Does nothing (returns ``None``) on success.

        If the iterable raises partway through, the exception
        propagates and the data must be considered unverified.

        :param chunks: An iterable of ``bytes``, may be a generator.
        :param signature: The detached signature from
            :meth:`sign_stream`.
        """
        verifier = self.new_verifier()

        for chunk in chunks:
            verifier.update(chunk)

        verifier.verify(signature)

    def validate_stream(self, chunks: cabc.Iterable[bytes], signature: bytes) -> bool:
        """Like :meth:`verify_stream`, but returns ``True`` or
        ``False`` instead of raising :class:`BadSignature`.
        """
        try:
            self.verify_stream(chunks, signature)
            return True
        except BadSignature:
            return False

    def iter_verified(
        self, chunks: cabc.Iterable[bytes], signature: bytes
    ) -> cabc.Iterator[bytes]:
        """Yield each chunk of the stream, then verify the signature
        at EOF. Raises :class:`BadSignature` after the last chunk if
        the stream did not match.

        .. warning::

            Chunks are yielded *before* the signature is verified.
            Consumers must treat yielded data as untrusted and must
            not commit it (save, execute, display as authentic) until
            the generator has been fully exhausted without raising.
            For a re-readable source, prefer calling
            :meth:`verify_stream` first and consuming the data only
            after it succeeds.
        """
        verifier = self.new_verifier()

        for chunk in chunks:
            checked = _check_chunk(chunk)
            verifier.update(checked)
            yield checked

        verifier.verify(signature)


class StreamVerifier:
    """Incrementally verifies a streamed payload against a detached
    signature. Created by :meth:`StreamSigner.new_verifier`.

    Feed each chunk with :meth:`update`. Only after the stream has
    reached EOF, call :meth:`verify` with the expected signature;
    there is no way to confirm success before that point.

    .. versionadded:: 2.3
    """

    def __init__(self, signer: StreamSigner):
        # One MAC per secret key to support key rotation. The number
        # of keys is expected to be small.
        self._macs: list[hmac.HMAC] = [
            signer._new_mac(key) for key in reversed(signer.secret_keys)
        ]
        self._length: int = 0
        self._finalized: bool = False

    @property
    def length(self) -> int:
        """The number of payload bytes fed to :meth:`update` so far."""
        return self._length

    def update(self, chunk: bytes) -> None:
        """Feed the next chunk of the payload. Must not be called
        after :meth:`verify`.
        """
        if self._finalized:
            raise RuntimeError("cannot update the verifier after verify was called")

        checked = _check_chunk(chunk)

        for mac in self._macs:
            mac.update(checked)

        self._length += len(checked)

    def verify(self, signature: str | bytes) -> None:
        """Verify the streamed payload against the detached
        ``signature``. Call this exactly once, after the stream has
        reached EOF. Raises :class:`BadSignature` if the payload does
        not match, including if it was truncated or extended. Does
        nothing (returns ``None``) on success.
        """
        self._finalized = True

        try:
            sig = base64_decode(signature)
        except Exception:
            raise BadSignature(f"Signature {signature!r} is not valid base64")

        packed_length = _pack_length(self._length)

        for mac in self._macs:
            final = mac.copy()
            final.update(packed_length)

            if hmac.compare_digest(sig, final.digest()):
                return

        raise BadSignature(f"Signature {signature!r} does not match")
