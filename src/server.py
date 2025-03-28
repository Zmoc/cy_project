import socket
import ssl

# Create an SSL context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="certs/server.crt", keyfile="certs/server.key")

# Create a TCP socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind(("0.0.0.0", 12345))
    server_socket.listen(5)
    print("Secure server is listening...")

    # Wrap the socket with SSL
    with context.wrap_socket(server_socket, server_side=True) as secure_server:
        while True:  # Keep accepting multiple clients
            client_socket, addr = secure_server.accept()
            print(f"Secure connection from {addr}")

            with client_socket:
                # Receive data securely
                data = client_socket.recv(1024)
                print("Received:", data.decode())

                # Send response securely
                client_socket.send("Hello from secure server!".encode())
