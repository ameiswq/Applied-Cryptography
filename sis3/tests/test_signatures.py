import unittest

from rsa_core import generate_keypair, sign_message, verify_message


class TestRSASignatures(unittest.TestCase):
    def test_sign_and_verify(self):
        public_key, private_key = generate_keypair(1024)

        message = b"Digital signature test"
        signature = sign_message(message, private_key)

        self.assertTrue(verify_message(message, signature, public_key))

    def test_verify_fails_for_tampered_message(self):
        public_key, private_key = generate_keypair(1024)

        message = b"Original message"
        tampered_message = b"Original message!"
        signature = sign_message(message, private_key)

        self.assertFalse(verify_message(tampered_message, signature, public_key))

    def test_verify_fails_for_tampered_signature(self):
        public_key, private_key = generate_keypair(1024)

        message = b"Original message"
        signature = bytearray(sign_message(message, private_key))
        signature[0] ^= 0x01

        self.assertFalse(verify_message(message, bytes(signature), public_key))

    def test_verify_fails_with_wrong_public_key(self):
        public_key_1, private_key_1 = generate_keypair(1024)
        public_key_2, _ = generate_keypair(1024)

        message = b"Original message"
        signature = sign_message(message, private_key_1)

        self.assertFalse(verify_message(message, signature, public_key_2))


if __name__ == "__main__":
    unittest.main()