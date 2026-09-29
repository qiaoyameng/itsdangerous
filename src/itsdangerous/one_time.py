from __future__ import annotations

import abc
import secrets
import threading
import time
import typing as t

from .exc import BadData
from .exc import NonceStoreUnavailable
from .exc import TokenAlreadyConsumed
from .timed import TimedSerializer


class NonceStore(abc.ABC):
    """Storage backend for consumed one-time token nonces.

    Implementations must be safe to call from multiple threads or
    processes sharing the same tokens. A backend that cannot be reached
    must raise :exc:`.NonceStoreUnavailable` rather than fail open.

    .. versionadded:: 2.3
    """

    @abc.abstractmethod
    def consume(self, nonce: str, expires_at: float | None) -> bool:
        """Atomically mark ``nonce`` as consumed.

        :param nonce: The random nonce extracted from a valid token.
        :param expires_at: POSIX timestamp after which the record may be
            discarded, or ``None`` if the token does not expire and the
            record must be kept indefinitely.
        :return: ``True`` if this call consumed the nonce, ``False`` if
            it had already been consumed and the record is not expired.
        """

    @abc.abstractmethod
    def cleanup(self, now: float | None = None) -> int:
        """Discard records whose ``expires_at`` is in the past.

        :param now: POSIX timestamp to compare against, defaults to the
            current time.
        :return: The number of records removed.
        """


class InMemoryNonceStore(NonceStore):
    """Keeps consumed nonces in a dict guarded by a
    :class:`threading.Lock`. Only suitable for a single process; use a
    shared backend such as Redis or a database when tokens are consumed
    by multiple processes.

    .. versionadded:: 2.3
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._nonces: dict[str, float | None] = {}

    def consume(self, nonce: str, expires_at: float | None) -> bool:
        now = time.time()

        with self._lock:
            if nonce in self._nonces:
                existing = self._nonces[nonce]

                if existing is None or existing > now:
                    return False

                # The previous record expired, replace it.
            self._nonces[nonce] = expires_at
            return True

    def cleanup(self, now: float | None = None) -> int:
        if now is None:
            now = time.time()

        with self._lock:
            expired = [
                nonce
                for nonce, expires_at in self._nonces.items()
                if expires_at is not None and expires_at <= now
            ]

            for nonce in expired:
                del self._nonces[nonce]

        return len(expired)


class OneTimeSerializer:
    """Wraps a :class:`.TimedSerializer` to produce tokens that can be
    consumed only once, for example email confirmation links.

    Each token carries a random nonce alongside the payload and an
    optional purpose string. :meth:`inspect` validates the signature,
    purpose, and age without consuming the nonce, so it is safe to use
    for preview pages. :meth:`consume` performs the same validation and
    then atomically marks the nonce as consumed through the configured
    :class:`NonceStore`; a token whose nonce was already consumed raises
    :exc:`.TokenAlreadyConsumed`.

    Validation always happens before the store is touched, so a token
    with an invalid signature never burns its nonce. If the store cannot
    be reached, :exc:`.NonceStoreUnavailable` is raised and the token is
    not accepted.

    :param serializer: The timed serializer used to sign tokens.
    :param store: The nonce storage backend.
    :param purpose: Default purpose required in tokens, used when the
        ``purpose`` argument is not given to :meth:`dumps`,
        :meth:`inspect`, or :meth:`consume`.
    :param max_age: Default maximum token age in seconds, used when the
        ``max_age`` argument is not given to :meth:`inspect` or
        :meth:`consume`. ``None`` means tokens do not expire and nonces
        are kept indefinitely.
    :param nonce_bytes: Number of random bytes in each nonce.

    .. versionadded:: 2.3
    """

    def __init__(
        self,
        serializer: TimedSerializer[t.Any],
        store: NonceStore,
        purpose: str | None = None,
        max_age: int | None = None,
        nonce_bytes: int = 32,
    ) -> None:
        self.serializer = serializer
        self.store = store
        self.purpose = purpose
        self.max_age = max_age
        self.nonce_bytes = nonce_bytes

    def dumps(self, payload: t.Any, purpose: str | None = None) -> t.Any:
        """Create a signed one-time token carrying ``payload``."""
        envelope = {
            "nonce": secrets.token_urlsafe(self.nonce_bytes),
            "purpose": self.purpose if purpose is None else purpose,
            "payload": payload,
        }
        return self.serializer.dumps(envelope)

    def inspect(
        self, token: t.Any, purpose: str | None = None, max_age: int | None = None
    ) -> t.Any:
        """Validate the token's signature, purpose, and age, and return
        the payload. The nonce is *not* consumed, so this is safe to
        call for previewing a confirmation page. Raises the same
        exceptions as :meth:`consume` except
        :exc:`.TokenAlreadyConsumed` and :exc:`.NonceStoreUnavailable`.
        """
        envelope, _ = self._load_envelope(token, max_age)
        self._check_purpose(envelope, purpose)
        return envelope["payload"]

    def consume(
        self, token: t.Any, purpose: str | None = None, max_age: int | None = None
    ) -> t.Any:
        """Validate the token like :meth:`inspect`, then atomically
        consume its nonce and return the payload.

        Raises :exc:`.TokenAlreadyConsumed` if the nonce was consumed
        before, and :exc:`.NonceStoreUnavailable` if the storage backend
        cannot be reached. An invalid signature, purpose, or expired
        token raises before the store is touched, so it never consumes
        the nonce.
        """
        envelope, signed_at = self._load_envelope(token, max_age)
        self._check_purpose(envelope, purpose)
        effective_max_age = self.max_age if max_age is None else max_age

        if effective_max_age is None:
            expires_at = None
        else:
            expires_at = signed_at.timestamp() + effective_max_age

        try:
            fresh = self.store.consume(envelope["nonce"], expires_at)
        except NonceStoreUnavailable:
            raise
        except Exception as e:
            raise NonceStoreUnavailable(
                "The nonce store could not be reached; the token was not accepted."
            ) from e

        if not fresh:
            raise TokenAlreadyConsumed("This one-time token has already been consumed.")

        return envelope["payload"]

    def _load_envelope(
        self, token: t.Any, max_age: int | None
    ) -> tuple[dict[str, t.Any], t.Any]:
        effective_max_age = self.max_age if max_age is None else max_age
        envelope, signed_at = self.serializer.loads(
            token, max_age=effective_max_age, return_timestamp=True
        )

        if (
            not isinstance(envelope, dict)
            or not isinstance(envelope.get("nonce"), str)
            or "payload" not in envelope
        ):
            raise BadData("Malformed one-time token payload.")

        return envelope, signed_at

    def _check_purpose(self, envelope: dict[str, t.Any], purpose: str | None) -> None:
        expected = self.purpose if purpose is None else purpose

        if envelope.get("purpose") != expected:
            raise BadData("The token was created for a different purpose.")
