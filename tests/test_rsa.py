import unittest

from crypto_pkg.rsa.rsa_scheme import RSA


class TestRSA(unittest.TestCase):

    def test_rsa(self):
        rsa = RSA(k=100)
        primes = rsa.generate_primes()
        keys = rsa.generate_keys(primes.q, primes.p)
        c = RSA.encrypt_message(message="hello", e=keys.public, n=keys.modulus)
        a = 1