# QUIC client Initial vectors

Public numeric test vectors from RFC Editor:

- `rfc9001-client.hex`: [RFC 9001, Appendix A.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-A.2).
- `rfc9369-client.hex`: [RFC 9369, Appendix A.2](https://www.rfc-editor.org/rfc/rfc9369.html#section-A.2).
- `client-crypto.hex`: the expected CRYPTO frame from those appendices. Append
  zero-valued PADDING frames to reach the specified 1162-byte plaintext.

Both protected datagrams contain 1200 bytes. Rust unit tests and the independently
compiled pinned C implementation consume the same external vectors. These fixtures
are developer inputs and are excluded from the runtime ZIP.
