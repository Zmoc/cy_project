from src.classes.server import SecureServer

ca_server = SecureServer(
    host="0.0.0.0",
    port=12345,
    certfile="certs/server.crt",
    keyfile="certs/server.key",
    private_key="certs/server_private.pem",
)

ca_server.start()
