from __future__ import annotations

import collections.abc as cabc
import time
import typing as t
from datetime import datetime
from datetime import timezone

from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import bytes_to_int
from .encoding import int_to_bytes
from .encoding import want_bytes
from .exc import BadSignature
from .exc import BadTimeSignature
from .exc import SignatureExpired
from .exc import SignatureNotYetValid
from .serializer import _TSerialized
from .serializer import Serializer
from .signer import Signer

#: Marker field used by :class:`TimeWindowSigner` to distinguish its
#: tokens from :class:`TimestampSigner` tokens. It contains a character
#: outside the base64 alphabet, so it can never be a valid timestamp
#: field in the old format.
_WINDOW_MARKER = b"tw~1"

#: The largest timestamp that can be encoded in a token.
_MAX_TIMESTAMP = (1 << 64) - 1


class TimestampSigner(Signer):
    """Works like the regular :class:`.Signer` but also records the time
    of the signing and can be used to expire signatures. The
    :meth:`unsign` method can raise :exc:`.SignatureExpired` if the
    unsigning failed because the signature is expired.
    """

    def get_timestamp(self) -> int:
        """Returns the current timestamp. The function must return an
        integer.
        """
        return int(time.time())

    def timestamp_to_datetime(self, ts: int) -> datetime:
        """Convert the timestamp from :meth:`get_timestamp` into an
        aware :class`datetime.datetime` in UTC.

        .. versionchanged:: 2.0
            The timestamp is returned as a timezone-aware ``datetime``
            in UTC rather than a naive ``datetime`` assumed to be UTC.
        """
        return datetime.fromtimestamp(ts, tz=timezone.utc)

    def sign(self, value: str | bytes) -> bytes:
        """Signs the given string and also attaches time information."""
        value = want_bytes(value)
        timestamp = base64_encode(int_to_bytes(self.get_timestamp()))
        sep = want_bytes(self.sep)
        value = value + sep + timestamp
        return value + sep + self.get_signature(value)

    # Ignore overlapping signatures check, return_timestamp is the only
    # parameter that affects the return type.

    @t.overload
    def unsign(  # pyright: ignore
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        return_timestamp: t.Literal[False] = False,
    ) -> bytes: ...

    @t.overload
    def unsign(
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        return_timestamp: t.Literal[True] = True,
    ) -> tuple[bytes, datetime]: ...

    def unsign(
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        return_timestamp: bool = False,
    ) -> tuple[bytes, datetime] | bytes:
        """Works like the regular :meth:`.Signer.unsign` but can also
        validate the time. See the base docstring of the class for
        the general behavior. If ``return_timestamp`` is ``True`` the
        timestamp of the signature will be returned as an aware
        :class:`datetime.datetime` object in UTC.

        .. versionchanged:: 2.0
            The timestamp is returned as a timezone-aware ``datetime``
            in UTC rather than a naive ``datetime`` assumed to be UTC.
        """
        try:
            result = super().unsign(signed_value)
            sig_error = None
        except BadSignature as e:
            sig_error = e
            result = e.payload or b""

        sep = want_bytes(self.sep)

        # If there is no timestamp in the result there is something
        # seriously wrong. In case there was a signature error, we raise
        # that one directly, otherwise we have a weird situation in
        # which we shouldn't have come except someone uses a time-based
        # serializer on non-timestamp data, so catch that.
        if sep not in result:
            if sig_error:
                raise sig_error

            raise BadTimeSignature("timestamp missing", payload=result)

        value, ts_bytes = result.rsplit(sep, 1)

        # A time window token is not a timestamp token. Fail explicitly
        # rather than treating the marker as a timestamp.
        if ts_bytes == _WINDOW_MARKER:
            raise BadTimeSignature(
                "Time window token cannot be verified as a timestamp",
                payload=value,
            )

        ts_int: int | None = None
        ts_dt: datetime | None = None

        try:
            ts_int = bytes_to_int(base64_decode(ts_bytes))
        except Exception:
            pass

        # Signature is *not* okay. Raise a proper error now that we have
        # split the value and the timestamp.
        if sig_error is not None:
            if ts_int is not None:
                try:
                    ts_dt = self.timestamp_to_datetime(ts_int)
                except (ValueError, OSError, OverflowError) as exc:
                    # Windows raises OSError
                    # 32-bit raises OverflowError
                    raise BadTimeSignature(
                        "Malformed timestamp", payload=value
                    ) from exc

            raise BadTimeSignature(str(sig_error), payload=value, date_signed=ts_dt)

        # Signature was okay but the timestamp is actually not there or
        # malformed. Should not happen, but we handle it anyway.
        if ts_int is None:
            raise BadTimeSignature("Malformed timestamp", payload=value)

        # Check timestamp is not older than max_age
        if max_age is not None:
            age = self.get_timestamp() - ts_int

            if age > max_age:
                raise SignatureExpired(
                    f"Signature age {age} > {max_age} seconds",
                    payload=value,
                    date_signed=self.timestamp_to_datetime(ts_int),
                )

            if age < 0:
                raise SignatureExpired(
                    f"Signature age {age} < 0 seconds",
                    payload=value,
                    date_signed=self.timestamp_to_datetime(ts_int),
                )

        if return_timestamp:
            return value, self.timestamp_to_datetime(ts_int)

        return value

    def validate(self, signed_value: str | bytes, max_age: int | None = None) -> bool:
        """Only validates the given signed value. Returns ``True`` if
        the signature exists and is valid."""
        try:
            self.unsign(signed_value, max_age=max_age)
            return True
        except BadSignature:
            return False


class TimedSerializer(Serializer[_TSerialized]):
    """Uses :class:`TimestampSigner` instead of the default
    :class:`.Signer`.
    """

    default_signer: type[TimestampSigner] = TimestampSigner  # pyright: ignore

    def iter_unsigners(
        self, salt: str | bytes | None = None
    ) -> cabc.Iterator[TimestampSigner]:
        return t.cast("cabc.Iterator[TimestampSigner]", super().iter_unsigners(salt))

    # TODO: Signature is incompatible because parameters were added
    #  before salt.

    def loads(  # type: ignore[override]
        self,
        s: str | bytes,
        max_age: int | None = None,
        return_timestamp: bool = False,
        salt: str | bytes | None = None,
    ) -> t.Any:
        """Reverse of :meth:`dumps`, raises :exc:`.BadSignature` if the
        signature validation fails. If a ``max_age`` is provided it will
        ensure the signature is not older than that time in seconds. In
        case the signature is outdated, :exc:`.SignatureExpired` is
        raised. All arguments are forwarded to the signer's
        :meth:`~TimestampSigner.unsign` method.
        """
        s = want_bytes(s)
        last_exception = None

        for signer in self.iter_unsigners(salt):
            try:
                base64d, timestamp = signer.unsign(
                    s, max_age=max_age, return_timestamp=True
                )
                payload = self.load_payload(base64d)

                if return_timestamp:
                    return payload, timestamp

                return payload
            except SignatureExpired:
                # The signature was unsigned successfully but was
                # expired. Do not try the next signer.
                raise
            except BadSignature as err:
                last_exception = err

        raise t.cast(BadSignature, last_exception)

    def loads_unsafe(  # type: ignore[override]
        self,
        s: str | bytes,
        max_age: int | None = None,
        salt: str | bytes | None = None,
    ) -> tuple[bool, t.Any]:
        return self._loads_unsafe_impl(s, salt, load_kwargs={"max_age": max_age})


class TimeWindow(t.NamedTuple):
    """The validity window embedded in a token created by
    :class:`TimeWindowSigner`. Both values are aware
    :class:`~datetime.datetime` objects in UTC.

    .. versionadded:: 2.3
    """

    #: The token is not valid before this time.
    not_before: datetime

    #: The token is not valid after this time.
    expires_at: datetime


class TimeWindowSigner(Signer):
    """Works like the regular :class:`.Signer` but also embeds a
    validity window (``not_before`` and ``expires_at`` timestamps) in
    the signed value, so the token itself carries its effective and
    expiry time rather than relying on the verifier to choose a
    ``max_age``. The window fields are part of the signed value and
    cannot be changed without invalidating the signature.

    The :meth:`unsign` method raises :exc:`.SignatureNotYetValid` if
    the window has not started yet, and :exc:`.SignatureExpired` if it
    has ended. These are distinct subclasses of
    :exc:`.BadTimeSignature`.

    Tokens use a different format than :class:`TimestampSigner` and
    cannot be verified cross-format; attempting to do so raises
    :exc:`.BadTimeSignature`.

    :param clock: A callable that returns the current time in seconds
        since the epoch, used instead of :func:`time.time`. This allows
        injecting a controllable clock, for example in tests.

    .. versionadded:: 2.3
    """

    #: Marker field appended to the window, identifying the token
    #: format. It is part of the signed value.
    window_marker: bytes = _WINDOW_MARKER

    def __init__(
        self,
        *args: t.Any,
        clock: cabc.Callable[[], float] | None = None,
        **kwargs: t.Any,
    ):
        super().__init__(*args, **kwargs)
        self.clock = clock

    def get_timestamp(self) -> int:
        """Returns the current timestamp, using the injected ``clock``
        if one was given. The function must return an integer.
        """
        if self.clock is not None:
            return int(self.clock())

        return int(time.time())

    def timestamp_to_datetime(self, ts: int) -> datetime:
        """Convert a timestamp into an aware
        :class:`datetime.datetime` in UTC.
        """
        return datetime.fromtimestamp(ts, tz=timezone.utc)

    def _safe_datetime(self, ts: int | None) -> datetime | None:
        """Convert a timestamp to a datetime, returning ``None`` if it
        is missing or cannot be represented.
        """
        if ts is None:
            return None

        try:
            return self.timestamp_to_datetime(ts)
        except (ValueError, OSError, OverflowError):
            # Windows raises OSError
            # 32-bit raises OverflowError
            return None

    @staticmethod
    def _coerce_timestamp(value: int | datetime) -> int:
        if isinstance(value, datetime):
            return int(value.timestamp())

        return int(value)

    def sign(
        self,
        value: str | bytes,
        not_before: int | datetime | None = None,
        expires_at: int | datetime | None = None,
        expires_in: int | None = None,
    ) -> bytes:
        """Signs the given string and also attaches a validity window.

        :param not_before: Timestamp (or aware ``datetime``) at which
            the token becomes valid. Defaults to the current time.
        :param expires_at: Timestamp (or aware ``datetime``) at which
            the token expires.
        :param expires_in: Number of seconds after ``not_before`` at
            which the token expires. Used if ``expires_at`` is not
            given. One of the two must be provided.
        """
        value = want_bytes(value)

        if not_before is None:
            nbf = self.get_timestamp()
        else:
            nbf = self._coerce_timestamp(not_before)

        if expires_at is not None:
            exp = self._coerce_timestamp(expires_at)
        elif expires_in is not None:
            exp = nbf + expires_in
        else:
            raise ValueError("expires_at or expires_in is required")

        if nbf < 0:
            raise ValueError("not_before must not be negative")

        if exp < nbf:
            raise ValueError("expires_at must not be before not_before")

        if exp > _MAX_TIMESTAMP:
            raise ValueError("timestamps must fit in 64 bits")

        sep = want_bytes(self.sep)
        value = (
            value
            + sep
            + base64_encode(int_to_bytes(nbf))
            + sep
            + base64_encode(int_to_bytes(exp))
            + sep
            + self.window_marker
        )
        return value + sep + self.get_signature(value)

    # Ignore overlapping signatures check, return_timestamps is the only
    # parameter that affects the return type.

    @t.overload
    def unsign(  # pyright: ignore
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        clock_skew: int = 0,
        return_timestamps: t.Literal[False] = False,
    ) -> bytes: ...

    @t.overload
    def unsign(
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        clock_skew: int = 0,
        return_timestamps: t.Literal[True] = True,
    ) -> tuple[bytes, TimeWindow]: ...

    def unsign(
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        clock_skew: int = 0,
        return_timestamps: bool = False,
    ) -> tuple[bytes, TimeWindow] | bytes:
        """Works like the regular :meth:`.Signer.unsign` but also
        validates the embedded validity window against the current
        time.

        :param max_age: If provided, the token expires at most this
            many seconds after its ``not_before`` time. This can only
            tighten the window embedded in the token, never extend it.
        :param clock_skew: Number of seconds of clock skew to tolerate
            on both ends of the window. Must not be negative, a
            negative skew would expand the window.
        :param return_timestamps: If ``True``, return a tuple of the
            value and a :class:`TimeWindow` with the embedded window.
        """
        if clock_skew < 0:
            raise ValueError("clock_skew must not be negative")

        try:
            result = super().unsign(signed_value)
            sig_error = None
        except BadSignature as e:
            sig_error = e
            result = e.payload or b""

        sep = want_bytes(self.sep)

        if sep not in result:
            if sig_error:
                raise sig_error

            raise BadTimeSignature("Time window missing", payload=result)

        value, marker = result.rsplit(sep, 1)

        # A timestamp token (or anything else) is not a time window
        # token. Fail explicitly rather than misreading its fields.
        if marker != self.window_marker:
            raise BadTimeSignature("Time window marker missing", payload=result)

        nbf_int: int | None = None
        exp_int: int | None = None
        data_value = value

        try:
            window_part, exp_bytes = value.rsplit(sep, 1)
            data_value, nbf_bytes = window_part.rsplit(sep, 1)
            nbf_int = bytes_to_int(base64_decode(nbf_bytes))
            exp_int = bytes_to_int(base64_decode(exp_bytes))
        except Exception:
            data_value = value
            nbf_int = None
            exp_int = None

        # Signature is *not* okay. Raise a proper error now that we have
        # split the value and the window.
        if sig_error is not None:
            raise BadTimeSignature(
                str(sig_error),
                payload=data_value,
                date_signed=self._safe_datetime(nbf_int),
            )

        # Signature was okay but the window is not there or malformed.
        # Should not happen, but we handle it anyway.
        if nbf_int is None or exp_int is None:
            raise BadTimeSignature("Malformed time window", payload=data_value)

        now = self.get_timestamp()

        if now < nbf_int - clock_skew:
            raise SignatureNotYetValid(
                f"Signature not valid before {nbf_int}, now {now}",
                payload=data_value,
                date_signed=self._safe_datetime(nbf_int),
            )

        # The verifier may tighten the embedded window, never extend it.
        expires = exp_int

        if max_age is not None:
            expires = min(expires, nbf_int + max_age)

        if now > expires + clock_skew:
            raise SignatureExpired(
                f"Signature expired at {expires}, now {now}",
                payload=data_value,
                date_signed=self._safe_datetime(nbf_int),
            )

        if return_timestamps:
            try:
                window = TimeWindow(
                    not_before=self.timestamp_to_datetime(nbf_int),
                    expires_at=self.timestamp_to_datetime(exp_int),
                )
            except (ValueError, OSError, OverflowError) as exc:
                # Windows raises OSError
                # 32-bit raises OverflowError
                raise BadTimeSignature(
                    "Malformed timestamp", payload=data_value
                ) from exc

            return data_value, window

        return data_value

    def validate(
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        clock_skew: int = 0,
    ) -> bool:
        """Only validates the given signed value. Returns ``True`` if
        the signature exists and is valid and the current time is
        within the validity window.
        """
        try:
            self.unsign(signed_value, max_age=max_age, clock_skew=clock_skew)
            return True
        except BadSignature:
            return False


class TimeWindowSerializer(Serializer[_TSerialized]):
    """Uses :class:`TimeWindowSigner` instead of the default
    :class:`.Signer`.

    .. versionadded:: 2.3
    """

    default_signer: type[TimeWindowSigner] = TimeWindowSigner  # pyright: ignore

    def iter_unsigners(
        self, salt: str | bytes | None = None
    ) -> cabc.Iterator[TimeWindowSigner]:
        return t.cast("cabc.Iterator[TimeWindowSigner]", super().iter_unsigners(salt))

    def dumps(  # type: ignore[override]
        self,
        obj: t.Any,
        salt: str | bytes | None = None,
        not_before: int | datetime | None = None,
        expires_at: int | datetime | None = None,
        expires_in: int | None = None,
    ) -> _TSerialized:
        """Returns a signed string serialized with the internal
        serializer, embedding a validity window in the token. The
        window arguments are forwarded to
        :meth:`TimeWindowSigner.sign`.
        """
        payload = want_bytes(self.dump_payload(obj))
        rv = t.cast(TimeWindowSigner, self.make_signer(salt)).sign(
            payload,
            not_before=not_before,
            expires_at=expires_at,
            expires_in=expires_in,
        )

        if self.is_text_serializer:
            return rv.decode("utf-8")  # type: ignore[return-value]

        return rv  # type: ignore[return-value]

    # TODO: Signature is incompatible because parameters were added
    #  before salt.

    def loads(  # type: ignore[override]
        self,
        s: str | bytes,
        max_age: int | None = None,
        clock_skew: int = 0,
        return_timestamps: bool = False,
        salt: str | bytes | None = None,
    ) -> t.Any:
        """Reverse of :meth:`dumps`, raises :exc:`.BadSignature` if the
        signature validation fails. The embedded validity window is
        checked against the current time, raising
        :exc:`.SignatureNotYetValid` or :exc:`.SignatureExpired`. The
        ``max_age`` and ``clock_skew`` arguments are forwarded to the
        signer's :meth:`~TimeWindowSigner.unsign` method. The time
        check is applied uniformly, no matter which signer (including
        fallback signers) verified the signature.
        """
        s = want_bytes(s)
        last_exception = None

        for signer in self.iter_unsigners(salt):
            try:
                base64d, window = signer.unsign(
                    s,
                    max_age=max_age,
                    clock_skew=clock_skew,
                    return_timestamps=True,
                )
                payload = self.load_payload(base64d)

                if return_timestamps:
                    return payload, window

                return payload
            except (SignatureExpired, SignatureNotYetValid):
                # The signature was unsigned successfully but the time
                # check failed. Do not try the next signer.
                raise
            except BadSignature as err:
                last_exception = err

        raise t.cast(BadSignature, last_exception)

    def loads_unsafe(  # type: ignore[override]
        self,
        s: str | bytes,
        max_age: int | None = None,
        clock_skew: int = 0,
        salt: str | bytes | None = None,
    ) -> tuple[bool, t.Any]:
        return self._loads_unsafe_impl(
            s, salt, load_kwargs={"max_age": max_age, "clock_skew": clock_skew}
        )
