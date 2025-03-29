from src.classes.server import SecureServer


class CA_Server(SecureServer):
    def __init__(self, host, port, certfile, keyfile, private_key):
        super().__init__(host, port, certfile, keyfile, private_key)
