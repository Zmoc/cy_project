import base64

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def blind_message(message):
    """Blind the message by combining it with a random factor."""
    # Generate a random blinding factor (nonce)
    blinding_factor = get_random_bytes(32)
    message_bytes = message.encode()

    # Blind the message by XORing it with the blinding factor
    blinded_message = bytes(a ^ b for a, b in zip(message_bytes, blinding_factor))
    return blinded_message, blinding_factor


def unblind_signature(blinded_signature, blinding_factor):
    """Unblind the signature to get the original message's signature."""
    # Unblind the signature by XORing it with the blinding factor
    signature = base64.b64decode(blinded_signature)
    return bytes(a ^ b for a, b in zip(signature, blinding_factor))


def sign_blinded_message(private_key_path, blinded_message):
    """Sign the blinded message."""
    # Load the server's private key
    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())

    signer = PKCS1_v1_5.new(private_key)
    signature = signer.sign(blinded_message)
    return base64.b64encode(signature).decode()


def verify_signature(server_public_key_path, original_message, signature):
    """Verify the signature using the server's public key."""
    # Load the server's public key
    with open(server_public_key_path, "rb") as f:
        server_public_key = RSA.import_key(f.read())

    verifier = PKCS1_v1_5.new(server_public_key)
    return verifier.verify(original_message.encode(), signature)
