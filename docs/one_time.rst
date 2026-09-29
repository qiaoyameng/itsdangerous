.. currentmodule:: itsdangerous

One-Time Tokens
===============

Some tokens must only be usable once. For example, an email
confirmation link may be fetched by a link scanner or previewer before
the user actually clicks it, but the action it confirms should still
only happen once. :class:`OneTimeSerializer` wraps a
:class:`TimedSerializer` to provide this guarantee.

Each token embeds a random nonce. Validation is split into two steps:

-   :meth:`~OneTimeSerializer.inspect` verifies the signature, purpose,
    and age without touching the nonce store. It is safe to call any
    number of times, for example to render a preview page.
-   :meth:`~OneTimeSerializer.consume` performs the same validation,
    then atomically records the nonce in a :class:`NonceStore`. Only
    the first call for a given token succeeds; further calls raise
    :exc:`TokenConsumed`.

.. code-block:: python

    from itsdangerous import InMemoryNonceStore
    from itsdangerous import OneTimeSerializer
    from itsdangerous import TimedSerializer

    serializer = OneTimeSerializer(
        TimedSerializer("secret-key", salt="confirm"),
        InMemoryNonceStore(),
        purpose="confirm-email",
        max_age=3600,
    )

    token = serializer.dumps({"user_id": 42})

    # A previewer can validate the token without consuming it.
    data = serializer.inspect(token)

    # The first consume succeeds, any later one raises TokenConsumed.
    data = serializer.consume(token)

The nonce is only recorded after the signature, purpose, and age all
validate, so a forged or expired token never burns a nonce. If the
store raises :exc:`NonceStoreUnavailable`, the error propagates and the
token is not accepted; one-time guarantees are never silently dropped.

The included :class:`InMemoryNonceStore` is thread-safe and suitable
for single-process applications. Use its
:meth:`~InMemoryNonceStore.purge_expired` method to remove records for
tokens that have expired and can no longer be used. For multi-process
deployments, implement :class:`NonceStore` against shared storage such
as a database or Redis, keeping the check-and-record operation atomic.

.. autoclass:: OneTimeSerializer
    :members:

.. autoclass:: NonceStore
    :members:

.. autoclass:: InMemoryNonceStore
    :members:
