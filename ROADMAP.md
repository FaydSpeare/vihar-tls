## TODO

- Clean up ServerKX / ClientKX impl

- Check server certificate chain against local root certificates?

- Support client certificiate
    - Certificate Request
    - Client Certificate
    - Certificate Verify

- HelloRequest
- Need to finished reading before starting client.renegotiate

- =============================================

- Support ECDH(E) signature & certificate
    - Supported groups extension
    - EC point format extension

- Allow DSA cert

- Support RC4, 3DES, how could you test?

- Fixed DH

- RFC5246 D3 - setting for min and max key sizes



- Do sessions need to be invalidated when an fatal error occurs during handshake. E.g. illegal parameter when resuming session
- Do session tickets need to be invalidated for fatal alerts, how?
- servername a part of session?
