# Server Configuration
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 50000

# SSL Certificate Paths
CERT_FILE = "certs/server.crt"
KEY_FILE = "certs/server.key"
SERVER_PRIVATE_KEY = "certs/server_private.pem"
CLIENT_CERT_FILE = "certs/client.crt"
SERVER_PUBLIC_KEY = "certs/server_public.pem"

# Security Settings
AES_KEY_SIZE = 32  # 256-bit AES key
MAX_MESSAGE_SIZE = 4096

# Fingerprint Database Path
DB_PATH = "data/db/fing_hash.db"
