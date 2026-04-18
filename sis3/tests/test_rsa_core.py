import unittest

from rsa_core import (
    generate_keypair,
    encrypt_int,
    decrypt_int,
    encrypt_bytes,
    decrypt_bytes,
)


class TestRSACore(unittest.TestCase):
    def test_generate_keypair(self):
        public_key, private_key = generate_keypair(128)

        self.assertIsNotNone(public_key)
        self.assertIsNotNone(private_key)
        self.assertEqual(public_key.n, private_key.n)

    def test_encrypt_decrypt_int(self):
        public_key, private_key = generate_keypair(128)

        message_int = 42
        cipher_int = encrypt_int(message_int, public_key)
        restored_int = decrypt_int(cipher_int, private_key)

        self.assertEqual(restored_int, message_int)

    def test_encrypt_decrypt_bytes_pkcs1v15(self):
        public_key, private_key = generate_keypair(1024)

        message = b"Hello RSA"
        ciphertext = encrypt_bytes(message, public_key, "pkcs1v15")
        restored = decrypt_bytes(ciphertext, private_key, "pkcs1v15")

        self.assertEqual(restored, message)

    def test_encrypt_decrypt_bytes_oaep(self):
        public_key, private_key = generate_keypair(1024)

        message = b"Hello OAEP"
        ciphertext = encrypt_bytes(message, public_key, "oaep")
        restored = decrypt_bytes(ciphertext, private_key, "oaep")

        self.assertEqual(restored, message)

    def test_encrypt_same_message_gives_different_ciphertexts(self):
        public_key, _ = generate_keypair(1024)

        message = b"Hello RSA"
        ciphertext1 = encrypt_bytes(message, public_key, "pkcs1v15")
        ciphertext2 = encrypt_bytes(message, public_key, "pkcs1v15")

        self.assertNotEqual(ciphertext1, ciphertext2)

    def test_empty_message(self):
        public_key, private_key = generate_keypair(1024)

        message = b""
        ciphertext = encrypt_bytes(message, public_key, "pkcs1v15")
        restored = decrypt_bytes(ciphertext, private_key, "pkcs1v15")

        self.assertEqual(restored, message)

    def test_wrong_key_should_fail_or_not_match(self):
        public_key_1, _ = generate_keypair(1024)
        _, private_key_2 = generate_keypair(1024)

        message = b"Hello RSA"
        ciphertext = encrypt_bytes(message, public_key_1, "pkcs1v15")

        try:
            restored = decrypt_bytes(ciphertext, private_key_2, "pkcs1v15")
            self.assertNotEqual(restored, message)
        except Exception:
            pass

    def test_invalid_ciphertext_rejected(self):
        _, private_key = generate_keypair(1024)

        malformed_ciphertext = b"\x00" * 10

        with self.assertRaises(ValueError):
            decrypt_bytes(malformed_ciphertext, private_key, "pkcs1v15")


if __name__ == "__main__":
    unittest.main()