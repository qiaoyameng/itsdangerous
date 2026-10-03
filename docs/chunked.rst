.. module:: itsdangerous.chunked

Chunked Tokens
==============

Sometimes a signed token grows beyond what a single transport field can
carry, such as a cookie size limit. :class:`TokenChunker` splits a token
into a signed manifest and numbered, size-limited chunks, and reassembles
it later. It does not read or write cookies itself; the caller decides
where the manifest and chunks are stored.

The manifest binds a message identity (random by default, or
deterministic if given), the chunk count, the total length, and the
SHA-256 digest of the whole token. Each chunk binds the manifest it
belongs to and its own position, so chunks from two issuances cannot be
mixed.

.. code-block:: python

    from itsdangerous.chunked import TokenChunker

    chunker = TokenChunker("secret-key")
    message = chunker.split(token, max_chunk_bytes=3800)

    # store message.manifest and message.chunks, and delete any
    # message.stale_indices left over from a previously longer token

    result = chunker.join(manifest, chunks, max_total_bytes=1_000_000)
    if result.complete:
        token = result.token

.. autoclass:: TokenChunker
    :members:

.. autoclass:: ChunkedMessage

.. autoclass:: ReassemblyResult

.. autoexception:: ChunkError

.. autoexception:: ForeignChunkError

.. autoexception:: ExtraChunkError

.. autoexception:: ConflictingChunkError

.. autoexception:: ChunkBudgetError
