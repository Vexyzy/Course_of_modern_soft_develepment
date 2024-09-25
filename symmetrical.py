import os
"""
About dependencies os
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
"""
About dependencies Cipher and algorithms
"""

FIRST_BYTE_SIZE = 32
SECOND_BYTE_SIZE = 16


class symmetric_encryption:
    """
    Class for working with text by using Symmetric Encryption.
    """
    
    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a random symmetric key for ChaCha20.
        Returns:
        - bytes: A randomly generated symmetric key.
        """
        return os.urandom(FIRST_BYTE_SIZE)

    @staticmethod
    def encrypt_text(symmetric_key: bytes, text: bytes) -> bytes:
        """
        Encrypt the text using the provided symmetric key and 16-byte nonce.
        Args:
        - symmetric_key (bytes): Symmetric key for encryption.
        - text (bytes): Text to be encrypted.
        Returns:
        - bytes: Encrypted text, prepended by the 16-byte nonce.
        """
        nonce = os.urandom(SECOND_BYTE_SIZE)
        cipher = Cipher(
            algorithms.ChaCha20(
                symmetric_key, nonce[:SECOND_BYTE_SIZE]
            ),
            mode=None
        )
        encryptor = cipher.encryptor()
        encrypted_text = encryptor.update(text)
        return nonce + encrypted_text  

    @staticmethod
    def decrypt_text(symmetric_key: bytes, encrypted_text: bytes) -> bytes:
        """
        Decrypt the text using the provided symmetric key and 16-byte nonce.
        Args:
        - symmetric_key (bytes): Symmetric key for decryption.
        - encrypted_text (bytes): Encrypted text, prepended by the 16-byte nonce.
        Returns:
        - bytes: Decrypted plaintext.
        """
        nonce = encrypted_text[:SECOND_BYTE_SIZE]
        ciphertext = encrypted_text[SECOND_BYTE_SIZE:]
        cipher = Cipher(
            algorithms.ChaCha20(
                symmetric_key,
                nonce[:SECOND_BYTE_SIZE]
            ),
            mode=None
        )
        decrypt = cipher.decryptor()
        return decrypt.update(ciphertext)
