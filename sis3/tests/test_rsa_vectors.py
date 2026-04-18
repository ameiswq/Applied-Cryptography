import os
import sys
import unittest

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from rsa_core import PublicKey, PrivateKey, sign_message, verify_message


class TestRSAVectors(unittest.TestCase):

    def test_nist_pkcs1_v1_5_sha256_siggen_vector(self):
        n_hex = (
            "9d922c405da68a55993ca248a4a4ea93b2a7aeaf5fc6ed0a68e1adf7c2fd2765"
            "ea16275a1d72753140c8a513fbb50656769ba59caa4a963d4c268bf0f46c7e80"
            "a7c7e62b7601a2291f578c8eef06f11837c69c514b11cbca127c382610e6f0ba"
            "666209ab4ba8ea068e021f53eba105f963be30f9e74d00901a86c139a72f8e25"
        )

        e_hex = (
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000007aed3d"
        )

        d_hex = (
            "1176953856856f80646106f56654bb2f630652e67dd5ea94d7429175b2613baab"
            "880a429fcc2482970a764a179154a3280fe502b8a37e83fa5785f5fbaf689300"
            "93a8992cf786fe9b1542162244a1c3e583cae936aa9cbde8251fd69b48cd1f90"
            "8cc90ab8a9e7a593b350e1c85b2edd97756cb31596ac9835277bfe9c1d2bb55"
        )

        msg_hex = (
            "d427cdac8da1aa706db4967b1e722b939706b65b3f488285558e5a438fc449fe"
            "01bfa44b41ce4a1bc9922b319c1007da2d0578d87c79339f82978bc4cfbc37b2"
            "72ce549f19cfaebe79b23bb6f06de854694f987c81946a66e8373b0709076dcc"
            "edfde68e5ccd5bc346bbcef162b05569158d1e3195bfb0424e1473f385cc73b6"
        )

        expected_signature_hex = (
            "8f21b2f2c8f3b87617813730134b2de9b75d0a47ee7ddf0b8afedb23961a0c52"
            "9f5f0a80c9c473da991833fcc671e8ac97a400bef64658cfab195b506362f45a"
            "b4b10e04c4357e7ed0111cf38e60704e10ab0e287f34780162ca1164c0313abf"
            "d04ad543e2981d35f3c9c135bea8cc378182fc107b6f49622fc9228eea6c6124"
        )

        public_key = PublicKey(
            n=int(n_hex, 16),
            e=int(e_hex, 16),
        )
        private_key = PrivateKey(
            n=int(n_hex, 16),
            d=int(d_hex, 16),
            p=0,
            q=0,
        )

        message = bytes.fromhex(msg_hex)
        expected_signature = bytes.fromhex(expected_signature_hex)

        signature = sign_message(message, private_key)

        self.assertEqual(signature, expected_signature)
        self.assertTrue(verify_message(message, signature, public_key))


if __name__ == "__main__":
    unittest.main()