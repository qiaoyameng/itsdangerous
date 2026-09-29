from __future__ import annotations

import secrets
import threading
import typing as t
from datetime import datetime
from datetime import timedelta
from datetime import timezone

from .exc import BadPayload
from .exc import BadPurpose
from .exc import TokenConsumed
from .timed import TimedSerializer


class NonceStore(t.Protocol):
    """Interface for backends that record consumed one-time token
    nonces. Implementations must consume atomically: checking whether
    the nonce was already recorded and recording it must happen as a
    single operation, so that concurrent consumers cannot both succeed.

    Implementations should raise :exc:`.NonceStoreUnavailable` if the
    backend cannot be reached. This must not be treated as a successful
    consume, otherwise one-time guarantees are silently lost.
    """

    def consume(self, nonce: str, expires_at: datetime | None) -> None:
        """Atomically record ``nonce`` as consumed.

        :param nonce: The random nonce embedded in the token.
        :param expires_at: When the token carrying this nonce expires,
            after which the record may be cleaned up. ``None`` if the
            token does not expire.
        :raises TokenConsumed: The nonce was already consumed.
        :raises NonceStoreUnavailable: The backend could not be reached.
        """
        ...


class InMemoryNonceStore:
    """A :class:`NonceStore` that keeps consumed nonces in a dict,
    using a lock to make :meth:`consume` atomic across threads. This is
    useful for tests and single-process applications. Use
    :meth:`purge_expired` to remove records for tokens that can no
    longer be used anyway.

    .. versionadded:: 2.3
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._nonces: dict[str, datetime | None] = {}

    def consume(self, nonce: str, expires_at: datetime | None) -> None:
        with self._lock:
            if nonce in self._nonces:
                raise TokenConsumed("This token has already been consumed.")

            self._nonces[nonce] = expires_at

    def purge_expired(self, now: datetime | None = None) -> int:
        """Remove records whose token has expired. Returns the number
        of records removed. Records without an expiry are kept.

        :param now: The current time, defaults to
            ``datetime.now(timezone.utc)``.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        with self._lock:
            expired = [
                nonce
                for nonce, expires_at in self._nonces.items()
                if expires_at is not None and expires_at <= now
            ]

            for nonce in expired:
                del self._nonces[nonce]

        return len(expired)

    def __contains__(self, nonce: str) -> bool:
        with self._lock:
            return nonce in self._nonces

    def __len__(self) -> int:
        with self._lock:
            return len(self._nonces)


class OneTimeSerializer:
    """Wraps a :class:`.TimedSerializer` to create tokens that can only
    be consumed once, for example email confirmation links that may be
    previewed by link scanners before the user clicks them.

    Each dumped token embeds a random nonce alongside the payload and a
    purpose string. Validation is split into two steps:

    -   :meth:`inspect` only verifies the signature, purpose, and age.
        It never touches the nonce store, so it is safe for previews.
    -   :meth:`consume` performs the same validation, then atomically
        records the nonce through the :class:`NonceStore`. Only the
        first call for a given token succeeds; further calls raise
        :exc:`.TokenConsumed`.

    The nonce is only consumed after all validation passes, so an
    invalid signature, wrong purpose, or expired token never burns a
    nonce. If the store raises :exc:`.NonceStoreUnavailable`, the error
    propagates and the token is not accepted.

    :param serializer: The :class:`.TimedSerializer` used to sign and
        verify tokens.
    :param store: The :class:`NonceStore` used to record consumed
        nonces.
    :param purpose: A string identifying what the tokens are for, such
        as ``"confirm-email"``. Tokens created for a different purpose
        are rejected with :exc:`.BadPurpose`.
    :param max_age: Maximum age of a token in seconds, enforced during
        both :meth:`inspect` and :meth:`consume`. Also determines when
        consumed nonce records may be cleaned up. ``None`` disables
        expiry.
    :param nonce_bytes: Number of random bytes in each nonce.

    .. versionadded:: 2.3
    """

    def __init__(
        self,
        serializer: TimedSerializer[t.Any],
        store: NonceStore,
        purpose: str = "default",
        max_age: int | None = None,
        nonce_bytes: int = 32,
    ) -> None:
        self.serializer = serializer
        self.store = store
        self.purpose = purpose
        self.max_age = max_age
        self.nonce_bytes = nonce_bytes

    def dumps(self, obj: t.Any = None) -> str:
        """Create a signed one-time token carrying ``obj``. A fresh
        random nonce is embedded in every token.
        """
        return self.serializer.dumps(
            {
                "nonce": secrets.token_urlsafe(self.nonce_bytes),
                "purpose": self.purpose,
                "data": obj,
            }
        )

    def _load_validated(self, token: str | bytes) -> tuple[t.Any, str, datetime | None]:
        """Verify the signature, structure, purpose, and age of
        ``token``. Returns the payload, nonce, and expiry. Does not
        touch the nonce store.
        """
        loaded, date_signed = self.serializer.loads(
            token, max_age=self.max_age, return_timestamp=True
        )

        if (
            not isinstance(loaded, dict)
            or not isinstance(loaded.get("nonce"), str)
            or not isinstance(loaded.get("purpose"), str)
            or "data" not in loaded
        ):
            raise BadPayload("Not a one-time token payload.")

        if not secrets.compare_digest(loaded["purpose"], self.purpose):
            raise BadPurpose(
                f"Token purpose {loaded['purpose']!r} does not match"
                f" {self.purpose!r}."
            )

        expires_at: datetime | None = None

        if self.max_age is not None:
            expires_at = date_signed + timedelta(seconds=self.max_age)

        return loaded["data"], loaded["nonce"], expires_at

    def inspect(self, token: str | bytes) -> t.Any:
        """Validate the token and return its payload without consuming
        it. Safe to call any number of times, for example to render a
        confirmation page before the user clicks the link.
        """
        data, _, _ = self._load_validated(token)
        return data

    def consume(self, token: str | bytes) -> t.Any:
        """Validate the token, atomically record its nonce in the
        store, and return its payload.

        :raises TokenConsumed: The token was already consumed.
        :raises NonceStoreUnavailable: The store could not record the
            nonce. The token is not accepted in this case.
        """
        data, nonce, expires_at = self._load_validated(token)
        self.store.consume(nonce, expires_at)
        return data
