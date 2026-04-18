import unittest

from .test_math_utils import TestMathUtils
from .test_prime_utils import TestPrimeUtils
from .test_padding import TestPadding
from .test_sha256 import TestSHA256
from .test_rsa_core import TestRSACore
from .test_signatures import TestRSASignatures
from .test_rsa_vectors import TestRSAVectors


def suite():
    test_suite = unittest.TestSuite()

    loader = unittest.TestLoader()

    test_suite.addTests(loader.loadTestsFromTestCase(TestMathUtils))
    test_suite.addTests(loader.loadTestsFromTestCase(TestPrimeUtils))
    test_suite.addTests(loader.loadTestsFromTestCase(TestPadding))
    test_suite.addTests(loader.loadTestsFromTestCase(TestSHA256))
    test_suite.addTests(loader.loadTestsFromTestCase(TestRSACore))
    test_suite.addTests(loader.loadTestsFromTestCase(TestRSASignatures))
    test_suite.addTests(loader.loadTestsFromTestCase(TestRSAVectors))

    return test_suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())