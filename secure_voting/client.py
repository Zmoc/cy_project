import socket
import ssl

# Create an SSL context and load the server certificate
context = ssl.create_default_context()
context.load_verify_locations("certs/server.crt")  # Verify server certificate

# Create and connect the secure socket
with socket.create_connection(("127.0.0.1", 12345)) as client_socket:
    with context.wrap_socket(
        client_socket, server_hostname="127.0.0.1"
    ) as secure_socket:
        print("Secure connection established.")

        # Send data securely
        secure_socket.sendall(b"Hello from secure client!")

        # Receive response securely
        response = secure_socket.recv(1024)
        print("Secure server response:", response.decode())
