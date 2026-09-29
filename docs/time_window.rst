.. module:: itsdangerous.time_window

Signing With Time Windows
=========================

:class:`TimeWindowSerializer` signs both a not-before time and an
expiration time as part of the token. The token expiration remains
available even when the verifier does not pass max_age.

.. code-block:: python

    from itsdangerous import TimeWindowSerializer

    s = TimeWindowSerializer("secret-key", expires_in=3600)
    token = s.dumps({"id": 42})
    s.loads(token)

A verifier can shorten the lifetime and allow a small clock difference.
Clock skew may not be negative.

.. code-block:: python

    s.loads(token, max_age=300, clock_skew=5)

Expired and not-yet-valid tokens raise distinct exceptions so callers can
present different errors without treating untrusted timestamp data as
authoritative.

.. autoclass:: TimeWindowSerializer
    :members:
