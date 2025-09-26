import socket
import ssl
import hashlib

HOST = "127.0.0.1"
PORT = 65431

# Server knows the correct password hash
CORRECT_PASSWORD_HASH = hashlib.sha256(b"Secret123").hexdigest()

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations("ca.crt")
context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"[*] Secure mTLS server listening on {HOST}:{PORT}")

    with context.wrap_socket(sock, server_side=True) as ssock:
        conn, addr = ssock.accept()
        print(f"[+] Connection from {addr}")

        attempts = 0
        authenticated = False

        # Authentication loop
        while attempts < 3:
            conn.sendall(b"Enter password hash:\n")
            data = conn.recv(1024)
            if not data:
                break
            received_hash = data.decode().strip()

            if received_hash == CORRECT_PASSWORD_HASH:
                conn.sendall(b"AUTH_SUCCESS\n")
                print("[Server] Client authenticated successfully.")
                authenticated = True
                break
            else:
                attempts += 1
                conn.sendall(b"AUTH_FAIL\n")
                print(f"[Server] Client authentication failed. Attempt {attempts}/3")

        if not authenticated:
            print("[Server] Max attempts reached. Closing connection.")
            conn.close()
        else:
            # proceed with normal communication
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                message = data.decode().strip()
                if message.lower() == "exit":
                    print("[*] Client ended session.")
                    break
                print(f"[Client]: {message}")
                reply = input("[Server > ] ").strip()
                conn.sendall(reply.encode())

        conn.close()
        print("[*] Connection closed.")
