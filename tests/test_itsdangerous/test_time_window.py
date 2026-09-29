import hashlib
from datetime import datetime
from datetime import timezone
from functools import partial

import pytest

from itsdangerous.encoding import base64_encode
from itsdangerous.encoding import int_to_bytes
from itsdangerous.exc import BadSignature
from itsdangerous.exc import BadTimeSignature
from itsdangerous.exc import SignatureExpired
from itsdangerous.exc import SignatureNotYetValid
from itsdangerous.signer import Signer
from itsdangerous.timed import TimedSerializer
from itsdangerous.timed import TimestampSigner
from itsdangerous.timed import TimeWindow
from itsdangerous.timed import TimeWindowSerializer
from itsdangerous.timed import TimeWindowSigner


class FakeClock:
    def __init__(self, now=1000):
        self.now = now

    def __call__(self):
        return self.now

    def tick(self, seconds=1):
        self.now += seconds


MAX_TIMESTAMP = (1 << 64) - 1


class TestTimeWindowSigner:
    @pytest.fixture()
    def clock(self):
        return FakeClock()

    @pytest.fixture()
    def signer_factory(self, clock):
        return partial(TimeWindowSigner, secret_key="secret-key", clock=clock)

    @pytest.fixture()
    def signer(self, signer_factory):
        return signer_factory()

    def test_sign_unsign(self, signer):
        signed = signer.sign("value", expires_in=100)
        assert isinstance(signed, bytes)
        assert signer.unsign(signed) == b"value"
        assert signer.validate(signed)

    def test_return_timestamps(self, signer):
        signed = signer.sign("value", not_before=1000, expires_at=1100)
        value, window = signer.unsign(signed, return_timestamps=True)
        assert value == b"value"
        assert window == TimeWindow(
            not_before=datetime.fromtimestamp(1000, tz=timezone.utc),
            expires_at=datetime.fromtimestamp(1100, tz=timezone.utc),
        )
        assert window.not_before.tzinfo is not None

    def test_window_fields_are_signed(self, signer):
        signed = signer.sign("value", not_before=1000, expires_at=1100)
        value, nbf, exp, marker, sig = signed.rsplit(b".", 4)
        assert marker == signer.window_marker

        other = base64_encode(int_to_bytes(1200))

        for tampered in (
            b".".join((value, other, exp, marker, sig)),
            b".".join((value, nbf, other, marker, sig)),
        ):
            with pytest.raises(BadTimeSignature):
                signer.unsign(tampered)

    def test_boundary_seconds(self, signer, clock):
        signed = signer.sign("value", not_before=1000, expires_at=1100)

        clock.now = 1000
        assert signer.unsign(signed) == b"value"

        clock.now = 999
        with pytest.raises(SignatureNotYetValid):
            signer.unsign(signed)

        clock.now = 1100
        assert signer.unsign(signed) == b"value"

        clock.now = 1101
        with pytest.raises(SignatureExpired):
            signer.unsign(signed)

    def test_clock_skew_boundary(self, signer, clock):
        signed = signer.sign("value", not_before=1000, expires_at=1100)

        clock.now = 990
        assert signer.unsign(signed, clock_skew=10) == b"value"

        clock.now = 989
        with pytest.raises(SignatureNotYetValid):
            signer.unsign(signed, clock_skew=10)

        clock.now = 1110
        assert signer.unsign(signed, clock_skew=10) == b"value"

        clock.now = 1111
        with pytest.raises(SignatureExpired):
            signer.unsign(signed, clock_skew=10)

    def test_negative_clock_skew_rejected(self, signer):
        signed = signer.sign("value", expires_in=100)

        with pytest.raises(ValueError):
            signer.unsign(signed, clock_skew=-1)

        with pytest.raises(ValueError):
            signer.validate(signed, clock_skew=-10)

    def test_clock_rollback(self, signer, clock):
        signed = signer.sign("value", expires_in=100)
        assert signer.unsign(signed) == b"value"

        # The clock is rolled back to before the token was issued.
        clock.now = 950
        with pytest.raises(SignatureNotYetValid):
            signer.unsign(signed)

        # A bounded skew tolerates a small rollback.
        assert signer.unsign(signed, clock_skew=50) == b"value"

        with pytest.raises(SignatureNotYetValid):
            signer.unsign(signed, clock_skew=49)

    def test_max_age_tightens_window(self, signer, clock):
        signed = signer.sign("value", not_before=1000, expires_at=2000)

        clock.now = 1500
        assert signer.unsign(signed, max_age=600) == b"value"

        with pytest.raises(SignatureExpired):
            signer.unsign(signed, max_age=400)

        # max_age can never extend the embedded window.
        clock.now = 2001
        with pytest.raises(SignatureExpired):
            signer.unsign(signed, max_age=10_000)

    def test_huge_expires_at(self, signer, clock):
        signed = signer.sign("value", not_before=1000, expires_at=MAX_TIMESTAMP)
        assert signer.unsign(signed) == b"value"

        # The timestamp cannot be represented as a datetime.
        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed, return_timestamps=True)

        assert "Malformed" in str(exc_info.value)

    def test_huge_not_before(self, signer, clock):
        signed = signer.sign("value", not_before=1 << 63, expires_at=MAX_TIMESTAMP)

        with pytest.raises(SignatureNotYetValid) as exc_info:
            signer.unsign(signed)

        # Unrepresentable as a datetime, but must not crash.
        assert exc_info.value.date_signed is None

    def test_timestamp_out_of_range(self, signer):
        with pytest.raises(ValueError):
            signer.sign("value", expires_in=1 << 64)

    def test_sign_requires_expiry(self, signer):
        with pytest.raises(ValueError):
            signer.sign("value")

    def test_expires_before_not_before(self, signer):
        with pytest.raises(ValueError):
            signer.sign("value", not_before=1100, expires_at=1000)

    def test_negative_not_before(self, signer):
        with pytest.raises(ValueError):
            signer.sign("value", not_before=-1, expires_in=100)

    def test_datetime_arguments(self, signer):
        signed = signer.sign(
            "value",
            not_before=datetime.fromtimestamp(1000, tz=timezone.utc),
            expires_at=datetime.fromtimestamp(1100, tz=timezone.utc),
        )
        _, window = signer.unsign(signed, return_timestamps=True)
        assert window.not_before == datetime.fromtimestamp(1000, tz=timezone.utc)
        assert window.expires_at == datetime.fromtimestamp(1100, tz=timezone.utc)

    def test_exceptions_distinguishable(self, signer, clock):
        assert issubclass(SignatureNotYetValid, BadTimeSignature)
        assert issubclass(SignatureExpired, BadTimeSignature)
        assert not issubclass(SignatureNotYetValid, SignatureExpired)
        assert not issubclass(SignatureExpired, SignatureNotYetValid)

        signed = signer.sign("value", not_before=1000, expires_at=1100)

        clock.now = 999
        with pytest.raises(SignatureNotYetValid):
            signer.unsign(signed)

        clock.now = 1101
        with pytest.raises(SignatureExpired):
            signer.unsign(signed)

    def test_window_missing(self, signer):
        other = Signer("secret-key")
        signed = other.sign("value")

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert "missing" in str(exc_info.value)

    def test_cross_format_timestamp_signer(self, signer, clock):
        timed = TimestampSigner("secret-key")
        timed_signed = timed.sign("value")

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(timed_signed)

        assert "marker" in str(exc_info.value)

        window_signed = signer.sign("value", expires_in=100)

        with pytest.raises(BadTimeSignature) as exc_info:
            timed.unsign(window_signed)

        assert "Time window" in str(exc_info.value)

    def test_changed_value(self, signer):
        signed = signer.sign("my string", expires_in=100)
        changed = signed.replace(b"my", b"other", 1)

        with pytest.raises(BadSignature):
            signer.unsign(changed)


class TestTimeWindowSerializer:
    @pytest.fixture()
    def clock(self):
        return FakeClock()

    @pytest.fixture()
    def serializer_factory(self, clock):
        return partial(
            TimeWindowSerializer,
            secret_key="secret_key",
            signer_kwargs={"clock": clock},
        )

    @pytest.fixture()
    def serializer(self, serializer_factory):
        return serializer_factory()

    @pytest.fixture()
    def value(self):
        return {"id": 42}

    def test_roundtrip(self, serializer, value):
        signed = serializer.dumps(value, expires_in=100)
        assert serializer.loads(signed) == value

    def test_return_timestamps(self, serializer, value):
        signed = serializer.dumps(value, not_before=1000, expires_at=1100)
        payload, window = serializer.loads(signed, return_timestamps=True)
        assert payload == value
        assert window.not_before == datetime.fromtimestamp(1000, tz=timezone.utc)
        assert window.expires_at == datetime.fromtimestamp(1100, tz=timezone.utc)

    def test_expired(self, serializer, value, clock):
        signed = serializer.dumps(value, expires_in=10)
        clock.tick(11)

        with pytest.raises(SignatureExpired) as exc_info:
            serializer.loads(signed)

        assert serializer.load_payload(exc_info.value.payload) == value

    def test_not_yet_valid(self, serializer, value, clock):
        signed = serializer.dumps(value, not_before=2000, expires_in=100)

        with pytest.raises(SignatureNotYetValid):
            serializer.loads(signed)

    def test_negative_clock_skew_rejected(self, serializer, value):
        signed = serializer.dumps(value, expires_in=100)

        with pytest.raises(ValueError):
            serializer.loads(signed, clock_skew=-1)

    def test_loads_unsafe(self, serializer, value, clock):
        signed = serializer.dumps(value, expires_in=10)
        assert serializer.loads_unsafe(signed) == (True, value)

        clock.tick(11)
        assert serializer.loads_unsafe(signed) == (False, value)

    def test_cross_format_timed_serializer(self, serializer, value, clock):
        timed = TimedSerializer("secret_key")
        timed_signed = timed.dumps(value)

        with pytest.raises(BadTimeSignature):
            serializer.loads(timed_signed)

        window_signed = serializer.dumps(value, expires_in=100)

        with pytest.raises(BadTimeSignature):
            timed.loads(window_signed)

    def test_fallback_signer_unified_time_check(self, value, clock):
        old_serializer = TimeWindowSerializer(
            "secret_key",
            signer_kwargs={"digest_method": hashlib.sha512, "clock": clock},
        )
        new_serializer = TimeWindowSerializer(
            "secret_key",
            signer_kwargs={"clock": clock},
            fallback_signers=[{"digest_method": hashlib.sha512, "clock": clock}],
        )

        # The primary signer rejects the signature, the fallback signer
        # verifies it, and the time check is still applied uniformly.
        signed = old_serializer.dumps(value, expires_in=10)
        assert new_serializer.loads(signed) == value

        clock.tick(11)
        with pytest.raises(SignatureExpired):
            new_serializer.loads(signed)

        # Same for a token whose window has not started yet.
        clock.now = 2000
        signed = old_serializer.dumps(value, expires_in=100)
        clock.now = 1500

        with pytest.raises(SignatureNotYetValid):
            new_serializer.loads(signed)
