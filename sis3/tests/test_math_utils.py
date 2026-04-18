import unittest

from math_utils import gcd, extended_gcd, mod_inverse, mod_exp


class TestMathUtils(unittest.TestCase):
    def test_gcd(self):
        self.assertEqual(gcd(48, 18), 6)
        self.assertEqual(gcd(17, 31), 1)
        self.assertEqual(gcd(0, 5), 5)

    def test_extended_gcd(self):
        g, x, y = extended_gcd(3, 11)
        self.assertEqual(g, 1)
        self.assertEqual(3 * x + 11 * y, 1)

    def test_mod_inverse(self):
        self.assertEqual(mod_inverse(3, 11), 4)
        self.assertEqual((3 * mod_inverse(3, 11)) % 11, 1)

    def test_mod_exp(self):
        self.assertEqual(mod_exp(2, 10, 1000), 24)
        self.assertEqual(mod_exp(5, 0, 13), 1)
        self.assertEqual(mod_exp(7, 2, 10), 9)


if __name__ == "__main__":
    unittest.main()