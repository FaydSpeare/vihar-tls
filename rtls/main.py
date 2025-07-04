import socket
import ssl

# Paths to your certificate and private key
CERT_FILE = 'server.crt'
KEY_FILE = 'server.key'

# Basic server config
HOST = '127.0.0.1'
PORT = 8443

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.set_ciphers("DEFAULT:@SECLEVEL=1")
context.set_ciphers("AES128-SHA:@SECLEVEL=1")

context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable TLS < 1.2
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_2


context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

for x in context.get_ciphers():
    print(x)
    print()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"TLS1.2 server listening on https://{HOST}:{PORT}")

    with context.wrap_socket(sock, server_side=True) as ssock:
        conn, addr = ssock.accept()
        print(f"Connection from {addr}")

        # Read data
        data = conn.recv(1024)
        print("Received:", data.decode())

        # Send reply
        conn.sendall(b"Hello over TLS!")
        conn.close()
