import threading
from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest
from freezegun import freeze_time

from itsdangerous.exc import BadPayload
from itsdangerous.exc import BadPurpose
from itsdangerous.exc import BadSignature
from itsdangerous.exc import NonceStoreUnavailable
from itsdangerous.exc import SignatureExpired
from itsdangerous.exc import TokenConsumed
from itsdangerous.one_time import InMemoryNonceStore
from itsdangerous.one_time import OneTimeSerializer
from itsdangerous.timed import TimedSerializer


@pytest.fixture()
def serializer():
    return TimedSerializer("secret-key", salt="one-time")


@pytest.fixture()
def store():
    return InMemoryNonceStore()


@pytest.fixture()
def one_time(serializer, store):
    return OneTimeSerializer(
        serializer, store, purpose="confirm-email", max_age=3600
    )


class UnavailableStore:
    """A store whose backend is temporarily down."""

    def __init__(self):
        self.calls = 0

    def consume(self, nonce, expires_at):
        self.calls += 1
        raise NonceStoreUnavailable("backend is down")


def test_inspect_does_not_consume(one_time):
    token = one_time.dumps({"user_id": 42})

    for _ in range(3):
        assert one_time.inspect(token) == {"user_id": 42}

    assert len(one_time.store) == 0
    assert one_time.consume(token) == {"user_id": 42}


def test_preview_then_confirm(one_time):
    token = one_time.dumps("confirm")

    # A link scanner previews the page, then the user confirms.
    assert one_time.inspect(token) == "confirm"
    assert one_time.consume(token) == "confirm"

    with pytest.raises(TokenConsumed):
        one_time.consume(token)


def test_consume_only_once(one_time):
    token = one_time.dumps()
    one_time.consume(token)

    with pytest.raises(TokenConsumed):
        one_time.consume(token)

    # Inspecting an already consumed token still validates, only
    # consuming is blocked.
    assert one_time.inspect(token) is None


def test_concurrent_consume_exactly_one_wins(one_time):
    token = one_time.dumps("prize")
    worker_count = 16
    barrier = threading.Barrier(worker_count)
    results = []
    errors = []

    def worker():
        barrier.wait()

        try:
            results.append(one_time.consume(token))
        except TokenConsumed:
            errors.append("consumed")

    threads = [threading.Thread(target=worker) for _ in range(worker_count)]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert results == ["prize"]
    assert errors == ["consumed"] * (worker_count - 1)
    assert len(one_time.store) == 1


def test_distinct_tokens_each_consume_once(one_time):
    tokens = [one_time.dumps(i) for i in range(10)]

    for i, token in enumerate(tokens):
        assert one_time.consume(token) == i

    assert len(one_time.store) == 10


def test_bad_signature_does_not_burn_nonce(one_time, store):
    token = one_time.dumps("data")
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")

    with pytest.raises(BadSignature):
        one_time.consume(tampered)

    assert len(store) == 0
    # The real token is unaffected and can still be consumed.
    assert one_time.consume(token) == "data"


def test_garbage_token_does_not_burn_nonce(one_time, store):
    with pytest.raises(BadSignature):
        one_time.consume("not-a-token")

    assert len(store) == 0


def test_wrong_purpose(serializer, store, one_time):
    other = OneTimeSerializer(serializer, store, purpose="reset-password")
    token = other.dumps("data")

    with pytest.raises(BadPurpose):
        one_time.consume(token)

    # Purpose mismatch must not burn the nonce.
    assert other.consume(token) == "data"


def test_expired_token_does_not_burn_nonce(serializer, store):
    one_time = OneTimeSerializer(serializer, store, max_age=60)

    with freeze_time("2026-01-01") as frozen:
        token = one_time.dumps("data")
        frozen.tick(timedelta(seconds=61))

        with pytest.raises(SignatureExpired):
            one_time.consume(token)

    assert len(store) == 0


def test_max_age_enforced_on_inspect(serializer, store):
    one_time = OneTimeSerializer(serializer, store, max_age=60)

    with freeze_time("2026-01-01") as frozen:
        token = one_time.dumps("data")
        frozen.tick(timedelta(seconds=61))

        with pytest.raises(SignatureExpired):
            one_time.inspect(token)


def test_store_unavailable_fails_closed(serializer):
    unavailable = UnavailableStore()
    one_time = OneTimeSerializer(serializer, unavailable, max_age=60)
    token = one_time.dumps("data")

    with pytest.raises(NonceStoreUnavailable):
        one_time.consume(token)

    # Validation happened before the store call, and the failure did
    # not silently accept the token.
    assert unavailable.calls == 1

    # Once the backend recovers the token can still be consumed, the
    # outage did not burn the nonce.
    one_time.store = InMemoryNonceStore()
    assert one_time.consume(token) == "data"


def test_non_one_time_payload_rejected(serializer, store, one_time):
    token = serializer.dumps({"plain": "payload"})

    with pytest.raises(BadPayload):
        one_time.consume(token)

    assert len(store) == 0


def test_unique_nonces(one_time):
    tokens = [one_time.dumps() for _ in range(100)]
    payloads = [one_time.serializer.loads(token) for token in tokens]
    nonces = {payload["nonce"] for payload in payloads}
    assert len(nonces) == 100


class TestInMemoryNonceStore:
    def test_consume_twice(self, store):
        store.consume("nonce", None)

        with pytest.raises(TokenConsumed):
            store.consume("nonce", None)

    def test_contains(self, store):
        assert "nonce" not in store
        store.consume("nonce", None)
        assert "nonce" in store

    def test_purge_expired(self, store):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        store.consume("expired", now - timedelta(seconds=1))
        store.consume("valid", now + timedelta(seconds=60))
        store.consume("no-expiry", None)

        assert store.purge_expired(now) == 1
        assert "expired" not in store
        assert "valid" in store
        assert "no-expiry" in store
        assert store.purge_expired(now) == 0

    def test_purge_expired_default_now(self, store):
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        store.consume("expired", past)
        assert store.purge_expired() == 1
        assert len(store) == 0

    def test_concurrent_consume_same_nonce(self, store):
        barrier = threading.Barrier(8)
        outcomes = []

        def worker():
            barrier.wait()

            try:
                store.consume("nonce", None)
                outcomes.append("ok")
            except TokenConsumed:
                outcomes.append("consumed")

        threads = [threading.Thread(target=worker) for _ in range(8)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert outcomes.count("ok") == 1
        assert outcomes.count("consumed") == 7


def test_consume_records_token_expiry(serializer, store):
    one_time = OneTimeSerializer(serializer, store, max_age=3600)

    with freeze_time("2026-01-01 00:00:00") as frozen:
        token = one_time.dumps()
        frozen.tick(timedelta(seconds=10))
        one_time.consume(token)

    expires_at = store._nonces[next(iter(store._nonces))]
    assert expires_at == datetime(2026, 1, 1, 1, 0, 0, tzinfo=timezone.utc)

    # After the token could no longer be used anyway, its record can
    # be cleaned up.
    assert store.purge_expired(expires_at) == 1
    assert len(store) == 0
