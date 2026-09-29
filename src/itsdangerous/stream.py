from __future__ import annotations

import collections.abc as cabc
import hashlib
import hmac
import typing as t

from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import want_bytes
from .exc import BadData
from .exc import BadSignature
from .signer import Signer


def _lazy_sha256(string: bytes = b"") -> t.Any:
    """Don't access ``hashlib.sha256`` until runtime, in case a FIPS
    build needs to configure something else first.
    """
    return hashlib.sha256(string)


class StreamSigner(Signer):
    """A signer that signs a stream of bytes in constant memory,
    producing a detached signature, and verifies such signatures
    incrementally.

    Unlike :class:`Signer`, the whole payload never needs to be held in
    memory. The body is fed through an HMAC chunk by chunk, then a final
    signature is computed over a frame that binds the caller-provided
    ``purpose`` and the total body length to the body digest::

        sig = HMAC(key, "itsdangerous-stream" | purpose | length | HMAC(key, body))

    Because the length is part of the signed frame, truncated or
    extended streams are rejected. Because the purpose is mixed into
    both the derived key (via the salt) and the signed frame, signatures
    made by a plain :class:`Signer` or by a ``StreamSigner`` with a
    different purpose are never accepted.

    The secret key should be a random string of ``bytes`` and should not
    be saved to code or version control.

    :param secret_key: The secret key to sign and verify with. Can be a
        list of keys, oldest to newest, to support key rotation.
    :param purpose: Caller-provided context that the signature is bound
        to, such as ``b"avatar-upload"``. Verification must use the same
        purpose. This provides domain separation between different uses
        of the same secret key.
    :param salt: Extra key to combine with ``secret_key`` and ``purpose``
        to distinguish signatures in different contexts.
    :param sep: Separator, only used to validate it is not in the base64
        alphabet. The detached signature itself contains no separator.
    :param key_derivation: How to derive the signing key from the secret
        key and salt. See :class:`Signer`.
    :param digest_method: Hash function to use for the streaming HMAC
        and the final signature. Defaults to :func:`hashlib.sha256`.

    .. versionadded:: 2.3
    """

    #: The default digest method for stream signing. Unlike
    #: :class:`Signer`, this modern API defaults to
    #: :func:`hashlib.sha256`.
    default_digest_method: t.Any = staticmethod(_lazy_sha256)

    #: Domain separation prefix in the signed frame, so a signature
    #: produced by a plain :class:`Signer` can never collide with a
    #: stream signature frame.
    _frame_prefix = b"itsdangerous-stream"

    def __init__(
        self,
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        purpose: str | bytes,
        salt: str | bytes | None = b"itsdangerous.StreamSigner",
        sep: str | bytes = b".",
        key_derivation: str | None = None,
        digest_method: t.Any | None = None,
    ):
        purpose_bytes = want_bytes(purpose)

        #: The purpose context this signer is bound to.
        self.purpose: bytes = purpose_bytes

        if salt is None:
            salt = b"itsdangerous.StreamSigner"

        # Mix the purpose into the salt (length-prefixed to avoid
        # ambiguity) so different purposes derive different keys.
        framed_salt = b":".join(
            [want_bytes(salt), str(len(purpose_bytes)).encode("ascii"), purpose_bytes]
        )
        super().__init__(
            secret_key,
            salt=framed_salt,
            sep=sep,
            key_derivation=key_derivation,
            digest_method=digest_method,
        )

    def _frame(self, length: int, body_digest: bytes) -> bytes:
        """Build the framed message that is actually signed. Binds the
        protocol version, purpose, and body length to the body digest.
        """
        return b".".join(
            [
                self._frame_prefix,
                str(len(self.purpose)).encode("ascii"),
                self.purpose,
                str(length).encode("ascii"),
                body_digest,
            ]
        )

    def _new_body_mac(self, key: bytes) -> hmac.HMAC:
        return hmac.new(key, digestmod=self.digest_method)

    def sign_stream(self, chunks: cabc.Iterable[bytes]) -> bytes:
        """Sign a one-shot iterable of bytes, returning a detached
        base64-encoded signature. The iterable is consumed exactly once
        and only one chunk is held in memory at a time.

        If the iterable raises partway through (for example an upstream
        read error), the exception propagates and no signature is
        produced.

        :param chunks: An iterable of ``bytes`` (or ``str``, which is
            encoded as UTF-8). May be empty.
        """
        key = self.derive_key()
        mac = self._new_body_mac(key)
        length = 0

        for chunk in chunks:
            chunk = want_bytes(chunk)
            mac.update(chunk)
            length += len(chunk)

        sig = self.algorithm.get_signature(key, self._frame(length, mac.digest()))
        return base64_encode(sig)

    def stream_verifier(self, sig: str | bytes) -> StreamVerifier:
        """Create an incremental verifier for a detached signature.
        Feed each chunk with :meth:`StreamVerifier.update`, then call
        :meth:`StreamVerifier.verify` exactly once the stream reaches
        EOF. The data must be considered untrusted until ``verify``
        returns without raising.
        """
        return StreamVerifier(self, sig)

    def verify_stream(self, sig: str | bytes, chunks: cabc.Iterable[bytes]) -> None:
        """Verify a detached signature against a one-shot iterable of
        bytes, consuming it completely. Raises :class:`BadSignature` if
        the stream does not match the signature, including when the
        stream is truncated or has appended bytes. Exceptions raised by
        the iterable itself propagate unchanged.
        """
        verifier = self.stream_verifier(sig)

        for chunk in chunks:
            verifier.update(chunk)

        verifier.verify()

    def validate_stream(
        self, sig: str | bytes, chunks: cabc.Iterable[bytes]
    ) -> bool:
        """Like :meth:`verify_stream`, but returns ``False`` instead of
        raising :class:`BadSignature`. Exceptions raised by the iterable
        itself still propagate.
        """
        try:
            self.verify_stream(sig, chunks)
            return True
        except BadSignature:
            return False

    def guard_stream(
        self, sig: str | bytes, chunks: cabc.Iterable[bytes]
    ) -> cabc.Iterator[bytes]:
        """Wrap a one-shot iterable of bytes, yielding each chunk while
        verifying incrementally. This is the safe way to consume
        unverified data as a stream:

        -   Chunks are yielded **before** the signature is confirmed, so
            the consumer must treat them as untrusted and must not
            commit them (for example, rename a temp file over the real
            file) until the generator is fully exhausted.
        -   If the stream does not match the signature, the generator
            raises :class:`BadSignature` after the last chunk, before
            iteration completes.
        -   Exceptions raised by the wrapped iterable propagate
            unchanged and are never converted to :class:`BadSignature`.

        Only one chunk is held in memory at a time.
        """
        verifier = self.stream_verifier(sig)

        for chunk in chunks:
            verifier.update(chunk)
            yield want_bytes(chunk)

        verifier.verify()


class StreamVerifier:
    """Incremental verifier for :class:`StreamSigner` detached
    signatures. Created by :meth:`StreamSigner.stream_verifier`.

    Feed the body with :meth:`update` chunk by chunk, then call
    :meth:`verify` once at EOF. Only a successful ``verify`` call marks
    the consumed data as trusted; :attr:`verified` is ``False`` until
    then.

    .. versionadded:: 2.3
    """

    def __init__(self, signer: StreamSigner, sig: str | bytes):
        try:
            self._sig: bytes = base64_decode(sig)
        except BadData as e:
            raise BadSignature("Invalid base64-encoded signature") from e

        self._signer = signer
        # Newest key first, matching Signer.verify_signature.
        self._macs: list[tuple[bytes, hmac.HMAC]] = []

        for secret_key in reversed(signer.secret_keys):
            key = signer.derive_key(secret_key)
            self._macs.append((key, signer._new_body_mac(key)))

        self._length = 0
        self._finished = False

        #: ``True`` only after :meth:`verify` succeeded. Until then, all
        #: data fed to this verifier must be considered untrusted.
        self.verified: bool = False

    @property
    def length(self) -> int:
        """The number of bytes fed to :meth:`update` so far."""
        return self._length

    def update(self, chunk: str | bytes) -> None:
        """Feed the next chunk of the stream. Must not be called after
        :meth:`verify`.
        """
        if self._finished:
            raise RuntimeError("cannot update a verifier after verify was called")

        chunk = want_bytes(chunk)

        for _, mac in self._macs:
            mac.update(chunk)

        self._length += len(chunk)

    def verify(self) -> None:
        """Confirm the signature now that the stream has reached EOF.
        Raises :class:`BadSignature` if the consumed bytes and their
        total length do not match the signature. No more chunks may be
        fed after this is called.
        """
        if self._finished:
            if self.verified:
                return

            raise BadSignature("Stream signature does not match")

        self._finished = True
        signer = self._signer

        for key, mac in self._macs:
            framed = signer._frame(self._length, mac.digest())

            if signer.algorithm.verify_signature(key, framed, self._sig):
                self.verified = True
                return

        raise BadSignature("Stream signature does not match")
