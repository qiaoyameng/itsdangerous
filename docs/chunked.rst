.. module:: itsdangerous.chunked

Chunked Tokens
==============

Use :class:`ChunkedSerializer` when a token is too large for one storage
field. It creates a signed manifest and separately signed, numbered chunks
without depending on cookies or another HTTP framework.

The manifest records a message ID, chunk count, total length, and SHA-256
digest of the complete token. Each chunk is bound to the manifest and its
position, so chunks from different issuances cannot be combined.

Splitting
---------

The return value contains the ``manifest``, ``chunks`` in index order, and
``delete_indices`` for stale fields from a previous, longer token. Pass
``previous_chunk_count`` to populate that cleanup plan.

.. code-block:: python

    from itsdangerous.chunked import ChunkedSerializer

    s = ChunkedSerializer("secret-key")
    result = s.dumps(token, max_chunk_bytes=4096, previous_chunk_count=6)

    # Save result.manifest separately, then save each result.chunks[i]
    # using the caller's chosen field naming scheme. Delete result.delete_indices.

A random message ID is used by default. Pass a deterministic ``message_id``
when the same logical message must have a stable identity.

Reassembling
------------

Chunks may be supplied as a mapping or iterable of ``(index, value)`` pairs
in any order. Duplicate identical chunks are accepted, while conflicting
duplicates, missing chunks, additional chunks, and chunks over the byte
budget raise distinct exceptions. The token bytes are only assembled after
the manifest and every chunk signature have been verified; the complete
length and digest are checked before returning.

.. code-block:: python

    result = s.loads(manifest, chunks, previous_chunk_count=6)
    token = result.token
    # Delete result.delete_indices after saving the successful token state.

API
---

.. autoclass:: ChunkedSerializer
    :members:

.. autoclass:: ChunkedToken
    :members:

.. autoclass:: ReassembledToken
    :members:
