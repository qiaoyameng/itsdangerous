Attenuated Tokens
=================

.. currentmodule:: itsdangerous

.. module:: itsdangerous.attenuation

:class:`Attenuator` issues macaroon-style tokens for cases such as
download authorization, where a token is handed to downstream parties
that may need to restrict it further but must never be able to loosen
the permissions they were given.

A token carries a payload and an ordered chain of caveats. The root
signature is ``HMAC(key, payload)`` and each caveat extends the chain
with ``HMAC(previous_signature, caveat)``. A holder can append a caveat
using only the token's current signature, without knowing the secret
key. Removing, reordering, or rewriting an existing caveat invalidates
the chain. Caveat fields are length-prefixed, so their serialization
has no concatenation ambiguity.

Only first-party caveats are supported. There is no third-party
discharge.

.. code-block:: python

    from itsdangerous import Attenuator, ByteLimit, OperationSet
    from itsdangerous import PathPrefix, RequestContext

    att = Attenuator("root-secret")

    # Root token for the whole reports tree.
    root = att.mint("account:7", [PathPrefix("/reports")])

    # First delegate narrows the path and operations.
    level1 = att.attenuate(root, PathPrefix("/reports/2026"))
    level1 = att.attenuate(level1, OperationSet({"read", "list"}))

    # Second delegate narrows further and caps the download size.
    level2 = att.attenuate(level1, OperationSet({"read"}))
    level2 = att.attenuate(level2, ByteLimit(1024))

    # The verifier supplies the actual request context. Every caveat
    # must be satisfied; unknown caveats are rejected, never skipped.
    payload = att.verify(
        level2,
        RequestContext(path="/reports/2026/q3.pdf", operation="read", size=512),
    )

Deleting the middle ``OperationSet`` caveat from ``level2``, swapping
two caveats, or rewriting ``/reports/2026`` to ``/reports`` all break
the chained signature and fail verification with
:exc:`BadSignature`.

Paths are normalized to segments before prefix matching, so ``.``,
``..``, and duplicate slashes cannot escape a prefix. Stacked
:class:`OperationSet` caveats intersect, and stacked
:class:`ByteLimit` caveats take the minimum, so appended caveats can
only tighten the token.

The number of caveats in a chain is bounded by ``max_caveats``
(default 32) to keep verification work bounded.

.. autoclass:: Attenuator
    :members:

.. autoclass:: RequestContext

.. autoclass:: Caveat
    :members:

.. autoclass:: PathPrefix

.. autoclass:: OperationSet

.. autoclass:: ByteLimit

.. autoexception:: itsdangerous.exc.BadAttenuatedToken

.. autoexception:: itsdangerous.exc.CaveatNotSatisfied
