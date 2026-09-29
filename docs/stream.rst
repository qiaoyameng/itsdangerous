.. module:: itsdangerous.stream

Streaming Interface
===================

The :class:`Signer` interface requires the entire payload in memory to
sign or verify it. For large payloads such as file uploads, use
:class:`StreamSigner` instead. It consumes the payload as a stream of
chunks in constant memory and produces a *detached* signature that is
stored or transmitted separately from the data.

.. code-block:: python

    from itsdangerous import StreamSigner

    s = StreamSigner("secret-key", purpose="avatar-upload")

    with open("big.bin", "rb") as f:
        sig = s.sign_stream(iter(lambda: f.read(65536), b""))

The ``purpose`` argument is required and binds the signature to a
caller-chosen context, so a signature made for one use cannot be
replayed for another. The signature is also bound to the exact length
of the payload, so truncated or extended streams are rejected, and to
a domain separation prefix, so signatures from :class:`Signer` (or any
other protocol) are never accepted even with the same key and salt.

To verify, stream the payload again. Success can only be determined
once the stream has reached EOF:

.. code-block:: python

    with open("big.bin", "rb") as f:
        s.verify_stream(iter(lambda: f.read(65536), b""), sig)

If the stream does not match, :exc:`~itsdangerous.exc.BadSignature` is
raised. If the source itself fails while reading, that exception
propagates and the data must be considered unverified.

For finer control, feed chunks one at a time with a verifier:

.. code-block:: python

    verifier = s.new_verifier()

    for chunk in source:
        verifier.update(chunk)

    verifier.verify(sig)  # only call this at EOF

Consuming Unverified Data Safely
--------------------------------

A streaming consumer inherently sees data before the signature can be
checked. Two patterns avoid trusting unverified data:

-   If the source can be read twice, call
    :meth:`~StreamSigner.verify_stream` first, then consume the data
    only after verification succeeds.
-   If the source is one-shot, write chunks to a temporary location
    with :meth:`~StreamSigner.iter_verified` and only commit (move,
    execute, display) the result after iteration completes without
    raising.

.. code-block:: python

    with open("big.bin.partial", "wb") as f:
        for chunk in s.iter_verified(source, sig):
            f.write(chunk)  # staged, not yet trusted

    os.replace("big.bin.partial", "big.bin")  # only if verified

.. autoclass:: StreamSigner
    :members:

.. autoclass:: StreamVerifier
    :members:
