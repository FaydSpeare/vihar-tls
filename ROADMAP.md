## TODO

- Fix bad decryption overflow panics

- Check server certificate chain against local root certificates?

- HelloRequest
- Need to finished reading before starting client.renegotiate

- =============================================

- Support ECDH(E) signature & certificate
    - Supported groups extension
    - EC point format extension

- Support RC4, 3DES, how could you test?

- Fixed DH

- RFC5246 D3 - setting for min and max key sizes

- Invalidate session when handshake failure?

- Do sessions need to be invalidated when an fatal error occurs during handshake. E.g. illegal parameter when resuming session
- Do session tickets need to be invalidated for fatal alerts, how?
- servername a part of session?


=== Questions ===
what to do about all the try_into().unwraps() when creating length prefixed vectors
