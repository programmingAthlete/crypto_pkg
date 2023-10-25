import unittest

from crypto_pkg.ciphers.asymmetric.rsa.rsa_scheme import RSA


class TestRSA(unittest.TestCase):

    def test_rsa(self):
        rsa = RSA(k=100)
        primes = rsa.generate_primes()
        message = 'hello'
        keys = rsa.generate_keys(primes.q, primes.p)
        c = RSA.encrypt_message(message=message, e=keys.public, n=keys.modulus)
        m = RSA.decrypt_message(cipher_text=c, d=keys.private, n=keys.modulus)
        self.assertEqual(message, m)
