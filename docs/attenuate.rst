.. module:: itsdangerous.attenuate

Attenuable Tokens
=================

An attenuable token is a bearer token whose holder can pass to a
downstream service together with extra restrictions, called *caveats*.
Each caveat is folded into a chained HMAC signature, so a holder can
only ever append restrictions. Removing, reordering, or rewriting an
existing caveat invalidates the signature. Only first-party caveats are
supported; there is no third-party discharge.

.. code-block:: python

    from itsdangerous import AttenuableToken, PathPrefixCaveat, OpsCaveat

    root = AttenuableToken.create("secret-key", "download:42")
    delegated = root.attenuate(PathPrefixCaveat("/data/team/"))
    delegated = delegated.attenuate(OpsCaveat({"read"}))
    token_string = delegated.serialize()

The verifier reconstructs the chain from its key and checks every
caveat against the actual request. Unknown caveats are never skipped;
they always cause verification to fail.

.. code-block:: python

    from itsdangerous import AttenuableToken, RequestContext

    token = AttenuableToken.deserialize(token_string)
    perms = token.verify(
        "secret-key",
        RequestContext(path="/data/team/q3.csv", op="read", num_bytes=512),
    )

The number of caveats is limited (``DEFAULT_MAX_CAVEATS``) so
verification work stays bounded.

.. autoclass:: AttenuableToken
    :members:

.. autoclass:: RequestContext

.. autoclass:: Permissions

.. autoclass:: Caveat

.. autoclass:: PathPrefixCaveat

.. autoclass:: OpsCaveat

.. autoclass:: MaxBytesCaveat
