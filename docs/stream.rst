Streaming Signatures
====================

.. currentmodule:: itsdangerous

:class:`Signer` requires the entire payload to be a single ``bytes``
object in memory. For large payloads such as file uploads, use
:class:`StreamSigner` instead. It signs a one-shot iterable of bytes in
constant memory and produces a *detached* signature that is stored or
transmitted separately from the data.

.. code-block:: python

    from itsdangerous import StreamSigner

    signer = StreamSigner("secret-key", purpose=b"avatar-upload")

    def read_chunks(f, size=65536):
        while chunk := f.read(size):
            yield chunk

    with open("big.bin", "rb") as f:
        sig = signer.sign_stream(read_chunks(f))

The signature binds the caller-provided ``purpose`` and the total body
length in addition to the body itself:

-   A signature made with a different ``purpose``, or by a plain
    :class:`Signer`, is never accepted, even with the same secret key.
-   A truncated stream, or one with bytes appended, fails verification
    because the length no longer matches.

Verifying
---------

Verification is also incremental. Feed chunks with
:meth:`StreamVerifier.update` and call :meth:`StreamVerifier.verify`
only once the stream has reached EOF. Data must be considered
**untrusted** until ``verify`` returns without raising.

.. code-block:: python

    verifier = signer.stream_verifier(sig)

    with open("big.bin", "rb") as f:
        for chunk in read_chunks(f):
            verifier.update(chunk)

    verifier.verify()  # raises BadSignature if invalid
    assert verifier.verified

:meth:`StreamSigner.verify_stream` consumes an iterable and raises
:class:`BadSignature` on mismatch; :meth:`StreamSigner.validate_stream`
returns ``False`` instead.

Consuming unverified data safely
--------------------------------

Often the data must be processed while it is being read, before the
signature can be confirmed. :meth:`StreamSigner.guard_stream` wraps an
iterable, yielding each chunk while verifying in the background, and
raises :class:`BadSignature` at EOF if the stream did not match. The
chunks it yields are *not yet trusted*; only clean exhaustion of the
generator proves integrity. Never commit the data (for example, rename
a temp file over the destination) before the generator finishes:

.. code-block:: python

    with open("big.bin.tmp", "wb") as out:
        try:
            for chunk in signer.guard_stream(sig, read_chunks(src)):
                out.write(chunk)  # untrusted, written to temp location
        except BadSignature:
            out.close()
            os.unlink("big.bin.tmp")
            raise

    os.rename("big.bin.tmp", "big.bin")  # only now is the data trusted

If the wrapped iterable itself raises (for example an upstream read
error), that exception propagates unchanged and is never converted to
:class:`BadSignature`.

Memory use
----------

Only one chunk is held in memory at a time, plus the constant-size HMAC
state, so peak memory does not grow with the size of the stream. The
test suite proves this by streaming tens of megabytes through signing
and verification while asserting that peak traced memory stays below a
small constant bound.
