from __future__ import annotations

import collections.abc as cabc
import time
import typing as t
from datetime import datetime
from datetime import timezone

from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import want_bytes
from .exc import BadData
from .exc import BadSignature
from .exc import BadTimeSignature
from .exc import SignatureExpired
from .exc import SignatureNotYetValid
from .serializer import _TSerialized
from .serializer import Serializer
from .signer import Signer


class _DefaultMaxAge:
    pass


_default_max_age = _DefaultMaxAge()


class TimeWindowSerializer(Serializer[_TSerialized]):
    """Sign data with explicit not-before and expiration timestamps.

    Unlike TimedSerializer, both times are part of the signed token. A
    verifier may shorten the token lifetime with max_age and allow a
    small, non-negative clock_skew.

    :param expires_in: Default lifetime in seconds used by dumps when
        no per-token lifetime is given.
    :param max_age: Alias for expires_in.
    :param clock_skew: Number of seconds of clock difference to tolerate
        on both sides of the window. Must be non-negative.
    :param clock: Callable returning the current Unix time in seconds.
        Useful for testing and for using a different clock source.
    """

    default_signer: type[Signer] = Signer
    format_marker: bytes = b"tw1"
    window_separator: bytes = b":"

    def __init__(
        self,
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        salt: str | bytes | None = b"itsdangerous",
        serializer: t.Any | None = None,
        serializer_kwargs: dict[str, t.Any] | None = None,
        signer: type[Signer] | None = None,
        signer_kwargs: dict[str, t.Any] | None = None,
        fallback_signers: list[
            dict[str, t.Any] | tuple[type[Signer], dict[str, t.Any]] | type[Signer]
        ]
        | None = None,
        expires_in: int | None = None,
        max_age: int | None = None,
        clock_skew: int = 0,
        clock: cabc.Callable[[], int | float] | None = None,
    ):
        super().__init__(
            secret_key,
            salt=salt,
            serializer=serializer,
            serializer_kwargs=serializer_kwargs,
            signer=signer,
            signer_kwargs=signer_kwargs,
            fallback_signers=fallback_signers,
        )

        if expires_in is not None and max_age is not None:
            raise ValueError("expires_in and max_age cannot be used together")

        if expires_in is not None and expires_in <= 0:
            raise ValueError("expires_in must be a positive number of seconds")

        if max_age is not None and max_age <= 0:
            raise ValueError("max_age must be a positive number of seconds")

        if clock_skew < 0:
            raise ValueError("clock_skew must be non-negative")

        self.expires_in: int | None = (
            expires_in if expires_in is not None else max_age
        )
        self.max_age: int | None = self.expires_in
        self.clock_skew: int = clock_skew
        self.clock: cabc.Callable[[], int | float] | None = clock

    def get_timestamp(self) -> int:
        """Return the current Unix timestamp in whole seconds.

        Subclasses can override this; an injected clock takes
        precedence when provided.
        """
        return int(time.time())

    def _now(self) -> int:
        if self.clock is None:
            return self.get_timestamp()

        return int(self.clock())

    def _timestamp(self, value: int | datetime, name: str) -> int:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                raise ValueError(f"{name} must be timezone-aware")

            return int(value.timestamp())

        return int(value)

    def _datetime(self, timestamp: int) -> datetime | None:
        try:
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    def dumps(
        self,
        obj: t.Any,
        salt: str | bytes | None = None,
        *,
        expires_in: int | None | _DefaultMaxAge = _default_max_age,
        max_age: int | None | _DefaultMaxAge = _default_max_age,
        expires_at: int | datetime | None = None,
        not_before: int | datetime | None = None,
    ) -> _TSerialized:
        """Serialize and sign obj with an explicit validity window.

        Exactly one of expires_in/max_age (the lifetime) or
        expires_at (an absolute expiration) must determine the end
        of the window. not_before defaults to the current time.
        """
        if isinstance(expires_in, _DefaultMaxAge):
            expires_in = self.expires_in

        if isinstance(max_age, _DefaultMaxAge):
            max_age = self.max_age
        elif expires_in is not None:
            raise ValueError("expires_in and max_age cannot be used together")

        lifetime = expires_in if expires_in is not None else max_age

        if lifetime is not None and expires_at is not None:
            raise ValueError("expires_in and expires_at cannot be used together")

        if expires_in is not None and expires_in <= 0:
            raise ValueError("expires_in must be a positive number of seconds")

        if max_age is not None and max_age <= 0:
            raise ValueError("max_age must be a positive number of seconds")

        now = self._now()
        if not_before is not None:
            starts_at = self._timestamp(not_before, "not_before")
        else:
            starts_at = now

        if expires_at is not None:
            ends_at = self._timestamp(expires_at, "expires_at")
        elif lifetime is not None:
            ends_at = starts_at + lifetime
        else:
            raise ValueError("Either expires_in or expires_at is required")

        if ends_at < starts_at:
            raise ValueError("expires_at must not be before not_before")

        payload = base64_encode(self.dump_payload(obj))
        starts_field = base64_encode(str(starts_at).encode("ascii"))
        ends_field = base64_encode(str(ends_at).encode("ascii"))
        sep = self.window_separator
        window = sep.join((self.format_marker, payload, starts_field, ends_field))
        signed = self.make_signer(salt).sign(window)

        if self.is_text_serializer:
            return t.cast(_TSerialized, signed.decode("ascii"))

        return t.cast(_TSerialized, signed)

    def _parse_window(self, signed: bytes) -> tuple[bytes, int, int]:
        prefix = self.format_marker + self.window_separator

        if not signed.startswith(prefix) or b"." in signed:
            raise BadTimeSignature(
                "Unsupported time window signature", payload=signed
            )

        parts = signed.split(self.window_separator)

        if len(parts) != 4:
            raise BadTimeSignature("Malformed time window", payload=None)

        try:
            payload = base64_decode(parts[1])
            starts_at = int(base64_decode(parts[2]).decode("ascii"))
            ends_at = int(base64_decode(parts[3]).decode("ascii"))
        except (BadData, UnicodeDecodeError, ValueError):
            raise BadTimeSignature("Malformed time window", payload=None) from None

        return payload, starts_at, ends_at

    def _validate_window(
        self,
        payload: bytes,
        starts_at: int,
        ends_at: int,
        max_age: int | None,
        clock_skew: int,
        now: int,
    ) -> None:
        if ends_at < starts_at:
            raise BadTimeSignature(
                "Signature expires before it becomes valid",
                payload=payload,
                date_signed=self._datetime(starts_at),
            )

        if now + clock_skew < starts_at:
            raise SignatureNotYetValid(
                f"Signature not valid until {starts_at}",
                payload=payload,
                date_signed=self._datetime(starts_at),
            )

        if now - clock_skew > ends_at:
            raise SignatureExpired(
                f"Signature expired at {ends_at}",
                payload=payload,
                date_signed=self._datetime(starts_at),
            )

        if max_age is not None and now - clock_skew - starts_at > max_age:
            raise SignatureExpired(
                f"Signature age exceeds {max_age} seconds",
                payload=payload,
                date_signed=self._datetime(starts_at),
            )

    @t.overload
    def loads(
        self,
        s: str | bytes,
        max_age: int | None = None,
        clock_skew: int | None = None,
        salt: str | bytes | None = None,
        return_timestamp: t.Literal[False] = False,
    ) -> t.Any: ...

    @t.overload
    def loads(
        self,
        s: str | bytes,
        max_age: int | None = None,
        clock_skew: int | None = None,
        salt: str | bytes | None = None,
        return_timestamp: t.Literal[True] = True,
    ) -> tuple[t.Any, datetime, datetime]: ...

    def loads(
        self,
        s: str | bytes,
        max_age: int | None = None,
        clock_skew: int | None = None,
        salt: str | bytes | None = None,
        return_timestamp: bool = False,
    ) -> t.Any:
        """Verify the signature and time window, then deserialize.

        max_age may shorten the token lifetime; it can never extend
        the signed expiration. clock_skew must be non-negative.

        :raises SignatureExpired: The current time is after the
            expiration (plus skew) or after the tightened max_age.
        :raises SignatureNotYetValid: The current time is before the
            not-before time (minus skew).
        """
        if max_age is not None and max_age < 0:
            raise ValueError("max_age must be non-negative")

        if clock_skew is None:
            clock_skew = self.clock_skew
        elif clock_skew < 0:
            raise ValueError("clock_skew must be non-negative")

        signed_value = want_bytes(s)
        now = self._now()
        last_exception: BadSignature | None = None

        for signer in self.iter_unsigners(salt):
            try:
                signed_payload = signer.unsign(signed_value)
                payload, starts_at, ends_at = self._parse_window(signed_payload)
                self._validate_window(
                    payload, starts_at, ends_at, max_age, clock_skew, now
                )
                loaded = self.load_payload(payload)

                if not return_timestamp:
                    return loaded

                starts_dt = self._datetime(starts_at)
                ends_dt = self._datetime(ends_at)

                if starts_dt is None or ends_dt is None:
                    raise BadTimeSignature(
                        "Malformed timestamp", payload=payload
                    )

                return loaded, starts_dt, ends_dt
            except (SignatureExpired, SignatureNotYetValid):
                raise
            except BadSignature as e:
                last_exception = e

        if last_exception is None:
            last_exception = BadSignature("No signer could unsign the value")

        raise last_exception

    def loads_unsafe(
        self,
        s: str | bytes,
        max_age: int | None = None,
        clock_skew: int | None = None,
        salt: str | bytes | None = None,
    ) -> tuple[bool, t.Any]:
        return self._loads_unsafe_impl(
            s,
            salt,
            load_kwargs={"max_age": max_age, "clock_skew": clock_skew},
        )
