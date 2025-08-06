## TODO

- Proper ClientKeyExchange handling

- Support ServerKeyExchange from server-side

- HelloRequest

- Delete session from store when rejected
- delete session when fatal alert
- Implement server session ticket issuance 

- Max fragmentation extension

- Check server certificate chain against local root certificates?

- Need to finished reading before starting client.renegotiate

- Support client certificiate
    - Certificate Request
    - Client Certificate
    - Certificate Verify

- Support ECDH(E) signature & certificate
    - Supported groups extension
    - EC point format extension

- Allow DSA cert

- Support RC4, 3DES, how could you test?

- Fixed DH

- RFC5246 D3 - setting for min and max key sizes

