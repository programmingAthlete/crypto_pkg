import unittest
import random

from crypto_pkg.DGHV.dghv import DGHV


class TestDGHVScheme(unittest.TestCase):

    def test_encrypt(self):
        m = 1
        tau = 10
        p = random.getrandbits(2700)
        e = DGHV.generate_public_key(p=p, tau=tau)
        c = DGHV.encrypt(m=m, e=e)
        d = DGHV.decrypt(c=c, p=p)
        self.assertEqual(m, d)

    def test_encrypt_full_message(self):
        m = "Hello World!"
        p = random.getrandbits(2700)
        e = DGHV.generate_public_key(p=p, tau=10)
        c = DGHV.encrypt_full_message(message=m, e=e)
        d = DGHV.decrypt_full_message(c=c, p=p)
        self.assertEqual(m, d)
