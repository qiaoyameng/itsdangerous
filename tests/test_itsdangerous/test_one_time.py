from __future__ import annotations

import threading
import time
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from functools import partial

import pytest
from freezegun import freeze_time

from itsdangerous.exc import BadData
from itsdangerous.exc import BadSignature
from itsdangerous.exc import NonceStoreUnavailable
from itsdangerous.exc import SignatureExpired
from itsdangerous.exc import TokenAlreadyConsumed
from itsdangerous.one_time import InMemoryNonceStore
from itsdangerous.one_time import NonceStore
from itsdangerous.one_time import OneTimeSerializer
from itsdangerous.url_safe import URLSafeTimedSerializer


@pytest.fixture()
def store():
    return InMemoryNonceStore()


@pytest.fixture()
def factory(store):
    return partial(
        OneTimeSerializer,
        serializer=URLSafeTimedSerializer("secret-key", salt="one-time"),
        store=store,
        purpose="confirm-email",
        max_age=3600,
    )


@pytest.fixture()
def ots(factory):
    return factory()


class TestOneTimeSerializer:
    def test_preview_then_confirm(self, ots):
        token = ots.dumps({"user_id": 42})

        # Previewing validates without consuming, any number of times.
        assert ots.inspect(token) == {"user_id": 42}
        assert ots.inspect(token) == {"user_id": 42}

        # Confirming consumes the nonce.
        assert ots.consume(token) == {"user_id": 42}

        # Inspecting still works afterwards, it only validates.
        assert ots.inspect(token) == {"user_id": 42}

    def test_consume_twice(self, ots):
        token = ots.dumps("payload")
        assert ots.consume(token) == "payload"

        with pytest.raises(TokenAlreadyConsumed):
            ots.consume(token)

    def test_distinct_tokens_are_independent(self, ots):
        token_a = ots.dumps("a")
        token_b = ots.dumps("b")
        assert ots.consume(token_a) == "a"
        assert ots.consume(token_b) == "b"

    def test_concurrent_consume_only_one_wins(self, ots):
        token = ots.dumps("payload")
        barrier = threading.Barrier(16)
        results: list[str] = []
        errors: list[Exception] = []

        def worker():
            barrier.wait()
            try:
                results.append(ots.consume(token))
            except TokenAlreadyConsumed as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(16)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert results == ["payload"]
        assert len(errors) == 15

    def test_bad_signature_does_not_burn_nonce(self, ots, store):
        token = ots.dumps("payload")
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")

        with pytest.raises(BadSignature):
            ots.consume(tampered)

        assert store._nonces == {}
        # The genuine token is still usable.
        assert ots.consume(token) == "payload"

    def test_wrong_purpose_rejected_without_burning_nonce(self, factory):
        ots = factory()
        token = ots.dumps("payload", purpose="change-password")

        with pytest.raises(BadData, match="purpose"):
            ots.consume(token)

        with pytest.raises(BadData, match="purpose"):
            ots.inspect(token)

        # Not consumed, can still be used for the right purpose.
        assert ots.consume(token, purpose="change-password") == "payload"

    def test_purpose_mismatch_between_tokens(self, factory):
        ots = factory()
        other = factory(purpose="unsubscribe")
        token = other.dumps("payload")

        with pytest.raises(BadData, match="purpose"):
            ots.consume(token)

    def test_expired_token_rejected_without_burning_nonce(self, ots, store):
        with freeze_time(datetime(2026, 9, 30, tzinfo=timezone.utc)) as frozen:
            token = ots.dumps("payload")
            frozen.tick(timedelta(seconds=3601))

            with pytest.raises(SignatureExpired):
                ots.consume(token)

            with pytest.raises(SignatureExpired):
                ots.inspect(token)

        assert store._nonces == {}

    def test_max_age_override_per_call(self, factory):
        ots = factory(max_age=None)

        with freeze_time(datetime(2026, 9, 30, tzinfo=timezone.utc)) as frozen:
            token = ots.dumps("payload")
            frozen.tick(timedelta(days=30))
            assert ots.consume(token) == "payload"

    def test_malformed_payload_rejected(self, ots):
        token = ots.serializer.dumps(["not", "an", "envelope"])

        with pytest.raises(BadData, match="Malformed"):
            ots.consume(token)

    def test_store_unavailable_does_not_fail_open(self, ots, store, monkeypatch):
        token = ots.dumps("payload")

        def down(nonce, expires_at):
            raise NonceStoreUnavailable("backend is down")

        monkeypatch.setattr(store, "consume", down)

        with pytest.raises(NonceStoreUnavailable):
            ots.consume(token)

    def test_store_error_wrapped_as_unavailable(self, ots, store, monkeypatch):
        token = ots.dumps("payload")

        def broken(nonce, expires_at):
            raise ConnectionError("connection refused")

        monkeypatch.setattr(store, "consume", broken)

        with pytest.raises(NonceStoreUnavailable):
            ots.consume(token)

    def test_store_unavailable_does_not_consume(self, ots, store, monkeypatch):
        token = ots.dumps("payload")

        def broken(nonce, expires_at):
            raise ConnectionError("connection refused")

        monkeypatch.setattr(store, "consume", broken)

        with pytest.raises(NonceStoreUnavailable):
            ots.consume(token)

        monkeypatch.undo()
        # Nothing was recorded, the token can still be consumed.
        assert ots.consume(token) == "payload"


class TestInMemoryNonceStore:
    def test_consume_returns_false_for_replay(self, store):
        assert store.consume("nonce", None) is True
        assert store.consume("nonce", None) is False

    def test_expired_record_can_be_replaced(self, store):
        past = 1000.0
        assert store.consume("nonce", past) is True
        assert store.consume("nonce", None) is True
        assert store.consume("nonce", None) is False

    def test_cleanup_removes_only_expired(self, store):
        now = time.time()
        store.consume("expired", now - 1000.0)
        store.consume("fresh", now + 1000.0)
        store.consume("permanent", None)

        assert store.cleanup(now=now) == 1
        assert store.consume("expired", None) is True
        assert store.consume("fresh", None) is False
        assert store.consume("permanent", None) is False

    def test_cleanup_defaults_to_current_time(self, store):
        store.consume("expired", 1.0)
        assert store.cleanup() == 1

    def test_concurrent_consume_is_atomic(self, store):
        barrier = threading.Barrier(32)
        wins: list[bool] = []

        def worker():
            barrier.wait()
            wins.append(store.consume("nonce", None))

        threads = [threading.Thread(target=worker) for _ in range(32)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert wins.count(True) == 1
        assert wins.count(False) == 31

    def test_nonce_store_is_abstract(self):
        with pytest.raises(TypeError):
            NonceStore()  # type: ignore[abstract]
