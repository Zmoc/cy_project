from OpenSSL import crypto

# Generate RSA key pair
server_key = crypto.PKey()
server_key.generate_key(crypto.TYPE_RSA, 2048)

# Export the private key
with open("certs/server_private.pem", "wb") as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key))

# Export the public key
with open("certs/server_public.pem", "wb") as f:
    f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, server_key))

print("RSA Key Pair Generated:")

# Create a new private key
ssl_key = crypto.PKey()
ssl_key.generate_key(crypto.TYPE_RSA, 2048)

# Create a self-signed certificate
cert = crypto.X509()
cert.get_subject().CN = "localhost"  # Common Name (CN) for localhost
cert.set_serial_number(1000)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # Valid for 1 year
cert.set_issuer(cert.get_subject())  # Self-signed certificate
cert.set_pubkey(ssl_key)

# Add extensions
extensions = [
    # Key Usage extension (critical)
    crypto.X509Extension(b"keyUsage", True, b"digitalSignature,keyEncipherment"),
    # Extended Key Usage extension
    crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
    # Subject Alternative Name (SAN) extension
    crypto.X509Extension(b"subjectAltName", False, b"DNS:localhost,IP:127.0.0.1"),
]

# Add the extensions to the certificate
cert.add_extensions(extensions)

# Sign the certificate with the private key
cert.sign(ssl_key, "sha256")

# Save the private key to a file
with open("certs/ssl_private.key", "wb") as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ssl_key))

# Save the certificate to a file
with open("certs/ssl_certificate.crt", "wb") as f:
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

print(
    "Private Key (server_private.key) and Certificate (server_certificate.crt) generated with SAN and extensions."
)
