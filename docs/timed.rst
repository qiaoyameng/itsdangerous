.. module:: itsdangerous.timed

Signing With Timestamps
=======================

If you want to expire signatures you can use the
:class:`TimestampSigner` class which adds timestamp information and
signs it. On unsigning you can validate that the timestamp is not older
than a given age.

.. code-block:: python

    from itsdangerous import TimestampSigner
    s = TimestampSigner('secret-key')
    string = s.sign('foo')

.. code-block:: python

    s.unsign(string, max_age=5)
    Traceback (most recent call last):
      ...
    itsdangerous.exc.SignatureExpired: Signature age 15 > 5 seconds

.. autoclass:: TimestampSigner
    :members:

.. autoclass:: TimedSerializer
    :members:

Signing With a Validity Window
==============================

If the token itself should carry its effective and expiry time, use
:class:`TimeWindowSigner` or :class:`TimeWindowSerializer`. The
``not_before`` and ``expires_at`` timestamps are part of the signed
value. The verifier can additionally tighten the window with
``max_age`` and tolerate a bounded, non-negative ``clock_skew``.

.. code-block:: python

    from itsdangerous import TimeWindowSerializer
    s = TimeWindowSerializer("secret-key")
    token = s.dumps({"id": 42}, expires_in=300)
    s.loads(token, max_age=60, clock_skew=5)

Before the window starts, :exc:`~itsdangerous.exc.SignatureNotYetValid`
is raised, which is distinct from
:exc:`~itsdangerous.exc.SignatureExpired`. These tokens cannot be
verified by :class:`TimestampSigner` or :class:`TimedSerializer`, and
vice versa.

.. autoclass:: TimeWindowSigner
    :members:

.. autoclass:: TimeWindowSerializer
    :members:

.. autoclass:: TimeWindow
    :members:
