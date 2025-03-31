import os

from OpenSSL import crypto


def create_directory(path="certs"):
    """Ensure the output directory exists."""
    os.makedirs(path, exist_ok=True)


def generate_rsa_keypair(bits=2048):
    """Generate an RSA key pair."""
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, bits)
    return key


def save_pem_file(filename, data):
    """Save a PEM file."""
    with open(filename, "wb") as f:
        f.write(data)


def generate_ssl_certificate(key, cn="localhost", days_valid=365):
    """Generate a self-signed SSL certificate."""
    cert = crypto.X509()
    cert.get_subject().CN = cn
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(days_valid * 86400)
    cert.set_issuer(cert.get_subject())  # Self-signed
    cert.set_pubkey(key)

    # Add extensions
    cert.add_extensions(
        [
            crypto.X509Extension(
                b"keyUsage", True, b"digitalSignature,keyEncipherment"
            ),
            crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
            crypto.X509Extension(
                b"subjectAltName", False, f"DNS:{cn},IP:127.0.0.1".encode()
            ),
        ]
    )

    cert.sign(key, "sha256")
    return cert


def main():
    create_directory()

    # Generate and save RSA key pair
    server_key = generate_rsa_keypair()
    save_pem_file(
        "certs/server_private.pem",
        crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key),
    )
    save_pem_file(
        "certs/server_public.pem",
        crypto.dump_publickey(crypto.FILETYPE_PEM, server_key),
    )
    print("✅ RSA Key Pair Generated")

    # Generate and save SSL certificate
    ssl_key = generate_rsa_keypair()
    ssl_cert = generate_ssl_certificate(ssl_key)
    save_pem_file(
        "certs/ssl_private.key", crypto.dump_privatekey(crypto.FILETYPE_PEM, ssl_key)
    )
    save_pem_file(
        "certs/ssl_certificate.crt",
        crypto.dump_certificate(crypto.FILETYPE_PEM, ssl_cert),
    )
    print("✅ SSL Certificate and Private Key Generated")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"⚠️ Error: {e}")
