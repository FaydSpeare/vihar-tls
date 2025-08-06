## TODO

- Support ServerKeyExchange from server-side

- Delete session from store when rejected
- delete session when fatal alert
- Implement server session ticket issuance 

- Record layer fragmentation on outgoing messages
- Max fragmentation extension

- Check server certificate chain against local root certificates?

- Support RC4, 3DES, how could you test?
- Fixed DH
- Allow DSA cert
- Support client certificiate
    - Certificate Request
    - Client Certificate
    - Certificate Verify

- Support ECDH(E) signature & certificate
    - Supported groups extension
    - EC point format extension

- RFC5246 D3 - setting for min and max key sizes

- Need to finished reading before starting renegotiation
