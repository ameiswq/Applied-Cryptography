import unittest

from padding import (
    pkcs1_v15_pad,
    pkcs1_v15_unpad,
    pkcs1_v15_signature_pad,
    pkcs1_v15_signature_verify,
    oaep_pad,
    oaep_unpad,
)
from sha256 import sha256_bytes


class TestPadding(unittest.TestCase):
    def test_pkcs1_v15_pad_unpad(self):
        message = b"hello"
        block_size = 32

        padded = pkcs1_v15_pad(message, block_size)
        self.assertEqual(len(padded), block_size)

        restored = pkcs1_v15_unpad(padded)
        self.assertEqual(restored, message)

    def test_pkcs1_v15_pad_too_long(self):
        message = b"a" * 30
        block_size = 32

        with self.assertRaises(ValueError):
            pkcs1_v15_pad(message, block_size)

    def test_pkcs1_v15_unpad_invalid_header(self):
        invalid = b"\x00\x01" + b"\xff" * 10 + b"\x00hello"

        with self.assertRaises(ValueError):
            pkcs1_v15_unpad(invalid)

    def test_pkcs1_v15_signature_pad_and_verify(self):
        digest = sha256_bytes(b"test message")
        block_size = 128

        encoded = pkcs1_v15_signature_pad(digest, block_size)

        self.assertEqual(len(encoded), block_size)
        self.assertTrue(pkcs1_v15_signature_verify(encoded, digest))

    def test_pkcs1_v15_signature_verify_fail_on_wrong_hash(self):
        digest1 = sha256_bytes(b"message 1")
        digest2 = sha256_bytes(b"message 2")
        block_size = 128

        encoded = pkcs1_v15_signature_pad(digest1, block_size)
        self.assertFalse(pkcs1_v15_signature_verify(encoded, digest2))

    def test_oaep_pad_unpad(self):
        message = b"hello"
        block_size = 128

        padded = oaep_pad(message, block_size)
        self.assertEqual(len(padded), block_size)

        restored = oaep_unpad(padded)
        self.assertEqual(restored, message)


if __name__ == "__main__":
    unittest.main()