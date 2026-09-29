import hashlib
from datetime import datetime
from datetime import timezone

import pytest

from itsdangerous import BadSignature
from itsdangerous import BadTimeSignature
from itsdangerous import SignatureExpired
from itsdangerous import SignatureNotYetValid
from itsdangerous.encoding import base64_encode
from itsdangerous.timed import TimedSerializer
from itsdangerous.time_window import TimeWindowSerializer


class Clock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value


@pytest.fixture()
def clock():
    return Clock(100)


@pytest.fixture()
def serializer(clock):
    return TimeWindowSerializer(
        "secret-key", max_age=10, clock=clock, clock_skew=0
    )


def test_signs_and_returns_window(serializer, clock):
    token = serializer.dumps({"id": 42})

    assert serializer.loads(token) == {"id": 42}
    assert serializer.loads(token, return_timestamp=True) == (
        {"id": 42},
        datetime.fromtimestamp(100, tz=timezone.utc),
        datetime.fromtimestamp(110, tz=timezone.utc),
    )


def test_explicit_window_and_expires_in(clock):
    serializer = TimeWindowSerializer("secret-key", clock=clock)
    start = datetime.fromtimestamp(200, tz=timezone.utc)
    token = serializer.dumps({}, expires_in=10, not_before=start)

    clock.value = 200
    assert serializer.loads(token) == {}

    clock.value = 211
    with pytest.raises(SignatureExpired):
        serializer.loads(token)


def test_expires_at_requires_not_before_before_expiration():
    serializer = TimeWindowSerializer("secret-key")

    with pytest.raises(ValueError):
        serializer.dumps({}, not_before=11, expires_at=10)


@pytest.mark.parametrize(
    ("current", "exception"),
    (
        (99, SignatureNotYetValid),
        (100, None),
        (110, None),
        (111, SignatureExpired),
    ),
)
def test_boundary_seconds(serializer, current, exception):
    token = serializer.dumps({"id": 42})
    serializer.clock.value = current

    if exception is None:
        assert serializer.loads(token) == {"id": 42}
    else:
        with pytest.raises(exception):
            serializer.loads(token)


@pytest.mark.parametrize(
    ("current", "exception"),
    (
        (98, SignatureNotYetValid),
        (99, None),
        (111, None),
        (112, SignatureExpired),
    ),
)
def test_clock_skew_boundaries(serializer, current, exception):
    token = serializer.dumps({"id": 42})
    serializer.clock.value = current

    if exception is None:
        assert serializer.loads(token, clock_skew=1) == {"id": 42}
    else:
        with pytest.raises(exception):
            serializer.loads(token, clock_skew=1)


def test_verifier_can_tighten_max_age(serializer):
    token = serializer.dumps({"id": 42})

    serializer.clock.value = 105
    assert serializer.loads(token, max_age=5) == {"id": 42}

    serializer.clock.value = 106
    with pytest.raises(SignatureExpired):
        serializer.loads(token, max_age=5)


def test_negative_clock_skew_is_rejected(clock):
    with pytest.raises(ValueError):
        TimeWindowSerializer("secret-key", clock=clock, clock_skew=-1)


def test_negative_verification_clock_skew_is_rejected(serializer):
    token = serializer.dumps({"id": 42})

    with pytest.raises(ValueError):
        serializer.loads(token, clock_skew=-1)


def test_clock_rollback_is_not_yet_valid(serializer):
    token = serializer.dumps({"id": 42})
    serializer.clock.value = 90

    with pytest.raises(SignatureNotYetValid):
        serializer.loads(token)

    assert serializer.loads(token, clock_skew=10) == {"id": 42}


def test_huge_timestamps_do_not_require_datetime_conversion(clock):
    starts = 10**100
    ends = 10**101
    serializer = TimeWindowSerializer("secret-key", clock=clock)
    token = serializer.dumps({}, not_before=starts, expires_at=ends)

    clock.value = starts
    assert serializer.loads(token) == {}

    clock.value = ends + 1
    with pytest.raises(SignatureExpired) as exc_info:
        serializer.loads(token)

    assert exc_info.value.date_signed is None


def test_time_fields_are_signed(serializer):
    token = serializer.dumps({"id": 42})
    window, signature = token.rsplit(".", 1)
    marker, payload, starts, ends = window.split(":")
    changed_window = ":".join(
        (marker, payload, base64_encode(b"99").decode("ascii"), ends)
    )
    changed_token = changed_window + "." + signature

    with pytest.raises(BadSignature):
        serializer.loads(changed_token)


def test_cross_format_validation_fails(clock):
    value = {"id": 42}
    timed = TimedSerializer("secret-key")
    windowed = TimeWindowSerializer("secret-key", clock=clock)
    old_token = timed.dumps(value)
    new_token = windowed.dumps(value, max_age=10)

    with pytest.raises(BadTimeSignature):
        windowed.loads(old_token)

    with pytest.raises(BadTimeSignature):
        timed.loads(new_token)


def test_fallback_signer_uses_shared_time_check(clock):
    signing = TimeWindowSerializer(
        "secret-key",
        max_age=10,
        clock=clock,
        signer_kwargs={"digest_method": hashlib.sha256},
    )
    verifying = TimeWindowSerializer(
        "secret-key",
        clock=clock,
        signer_kwargs={"digest_method": hashlib.sha1},
        fallback_signers=[{"digest_method": hashlib.sha256}],
    )
    token = signing.dumps({"id": 42})

    assert verifying.loads(token) == {"id": 42}

    clock.value = 111
    with pytest.raises(SignatureExpired):
        verifying.loads(token)
