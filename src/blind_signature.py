import base64

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


# Helper function to base64 encode/decode
def base64_encode(data):
    return base64.b64encode(data).decode()


def base64_decode(data):
    return base64.b64decode(data)


def blind_message(message, public_key):
    """Blind the message by encrypting it with a random blinding factor."""
    # Generate a random blinding factor (a random integer)
    blinding_factor = get_random_bytes(32)
    cipher_rsa = PKCS1_OAEP.new(public_key)

    # Encrypt the original message with the RSA public key
    blinded_message = cipher_rsa.encrypt(message.encode())

    return base64_encode(blinded_message), base64_encode(blinding_factor)


def unblind_signature(blinded_signature, blinding_factor, private_key):
    """Unblind the signature to get the original message's signature."""
    cipher_rsa = PKCS1_OAEP.new(private_key)

    # Decode the blinded signature
    blinded_signature_bytes = base64_decode(blinded_signature)

    # Decrypt the blinded signature using the private key
    signature = cipher_rsa.decrypt(blinded_signature_bytes)

    return signature


def sign_blinded_message(private_key_path, blinded_message):
    """Sign the blinded message."""
    # Load the server's private key
    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())

    cipher_rsa = PKCS1_OAEP.new(private_key)

    # Sign the blinded message
    signature = cipher_rsa.encrypt(blinded_message)

    # Return the signed blinded message (base64 encoded)
    return base64_encode(signature)


def verify_signature(server_public_key_path, original_message, signature):
    """Verify the signature using the server's public key."""
    # Load the server's public key
    with open(server_public_key_path, "rb") as f:
        server_public_key = RSA.import_key(f.read())

    # Verify the signature by decrypting the signed message
    cipher_rsa = PKCS1_OAEP.new(server_public_key)
    try:
        # Decrypt the signature to obtain the original message
        decrypted_message = cipher_rsa.decrypt(base64_decode(signature))

        # Verify the decrypted message matches the original message
        return decrypted_message.decode() == original_message
    except:
        return False
