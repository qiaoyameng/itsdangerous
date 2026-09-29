One-Time Tokens
===============

.. module:: itsdangerous

Some signed links, such as email confirmation URLs, must only be used
once, even though they may be *inspected* many times first (for example
by a preview page or a mail scanner). ``OneTimeSerializer`` wraps a
:class:`TimedSerializer` and separates the two operations:

-   ``inspect`` validates the signature, purpose, and age without
    consuming the token.
-   ``consume`` performs the same validation, then atomically marks the
    token's random nonce as consumed through a ``NonceStore``.

Validation always happens before the store is touched, so a token with
an invalid signature never burns its nonce. If the store cannot be
reached, :exc:`NonceStoreUnavailable` is raised and the token is not
accepted; it never fails open.

.. code-block:: python

    from itsdangerous import (
        InMemoryNonceStore,
        OneTimeSerializer,
        URLSafeTimedSerializer,
    )

    ots = OneTimeSerializer(
        serializer=URLSafeTimedSerializer("secret-key", salt="confirm"),
        store=InMemoryNonceStore(),
        purpose="confirm-email",
        max_age=3600,
    )

    token = ots.dumps({"user_id": 42})
    ots.inspect(token)  # preview, does not consume
    ots.consume(token)  # works once
    ots.consume(token)  # raises TokenAlreadyConsumed

.. autoclass:: OneTimeSerializer
    :members: dumps, inspect, consume

.. autoclass:: NonceStore
    :members: consume, cleanup

.. autoclass:: InMemoryNonceStore
    :members: consume, cleanup
