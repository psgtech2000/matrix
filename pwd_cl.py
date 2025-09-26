import socket
import ssl
import hashlib

HOST = "127.0.0.1"
PORT = 65431

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_cert_chain(certfile="client.crt", keyfile="client.key")
context.load_verify_locations("ca.crt")
context.check_hostname = False
context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        print(f"[*] Connected securely with mTLS to {HOST}:{PORT}")

        authenticated = False
        attempts = 0

        while attempts < 3 and not authenticated:
            # wait for server prompt
            server_msg = ssock.recv(1024).decode()
            print(f"[Server]: {server_msg.strip()}")

            # input password from user
            password = input("[Client] Enter password: ").strip()

            # hash password and send
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            ssock.sendall(password_hash.encode())

            # server response
            response = ssock.recv(1024).decode().strip()
            print(f"[Server]: {response}")

            if response == "AUTH_SUCCESS":
                authenticated = True
                print("[Client] Authentication successful! Proceeding...")
            else:
                attempts += 1
                print(f"[Client] Authentication failed. Attempt {attempts}/3")

        if not authenticated:
            print("[Client] Max attempts reached. Connection closed.")
        else:
            # proceed with communication
            while True:
                msg = input("[Client > ] ").strip()
                ssock.sendall(msg.encode())
                if msg.lower() in ("exit", "quit"):
                    print("[Client] Ending session.")
                    break
                reply = ssock.recv(1024).decode().strip()
                print(f"[Server]: {reply}")
