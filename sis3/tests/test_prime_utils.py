import unittest

from prime_utils import is_probable_prime, generate_prime, generate_distinct_primes


class TestPrimeUtils(unittest.TestCase):
    def test_small_primes(self):
        self.assertTrue(is_probable_prime(2))
        self.assertTrue(is_probable_prime(3))
        self.assertTrue(is_probable_prime(17))
        self.assertTrue(is_probable_prime(31))
        self.assertTrue(is_probable_prime(127))

    def test_small_composites(self):
        self.assertFalse(is_probable_prime(1))
        self.assertFalse(is_probable_prime(4))
        self.assertFalse(is_probable_prime(15))
        self.assertFalse(is_probable_prime(21))
        self.assertFalse(is_probable_prime(91))

    def test_carmichael_numbers(self):
        self.assertFalse(is_probable_prime(561))
        self.assertFalse(is_probable_prime(1105))
        self.assertFalse(is_probable_prime(1729))

    def test_generate_prime_16(self):
        p = generate_prime(16)
        self.assertTrue(is_probable_prime(p))
        self.assertGreaterEqual(p.bit_length(), 16)

    def test_generate_prime_512(self):
        p = generate_prime(512)
        self.assertTrue(is_probable_prime(p))
        self.assertGreaterEqual(p.bit_length(), 512)

    def test_generate_prime_1024(self):
        p = generate_prime(1024)
        self.assertTrue(is_probable_prime(p))
        self.assertGreaterEqual(p.bit_length(), 1024)

    def test_generate_distinct_primes(self):
        p, q = generate_distinct_primes(16)
        self.assertNotEqual(p, q)
        self.assertTrue(is_probable_prime(p))
        self.assertTrue(is_probable_prime(q))


if __name__ == "__main__":
    unittest.main()