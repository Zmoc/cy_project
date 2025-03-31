# Server Configuration
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 50000
CONNECTION_TIMEOUT = 30

# SSL Certificate Paths
CERT_FILE = "certs/ssl_certificate.crt"
KEY_FILE = "certs/ssl_private.key"
SERVER_PRIVATE_KEY = "certs/server_private.pem"
CLIENT_CERT_FILE = "certs/client.crt"
SERVER_PUBLIC_KEY = "certs/server_public.pem"

# Security Settings
AES_KEY_SIZE = 32  # 256-bit AES key
MAX_MESSAGE_SIZE = 4096

# Fingerprint Database Path
FING_DB = "data/db/fing_hash.db"
CLIENT_DB = "data/db/client_cache.db"
USER_DB = "data/db/user.db"
