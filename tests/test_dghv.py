import unittest
import random

from crypto_pkg.ciphers.asymmetric.DGHV.dghv import DGHV


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

        p = random.getrandbits(100)
        a = [[3.4682617565055593e+34, 3.4682617565053624e+34, 3.4682617565053933e+34, 3.4682617565053914e+34,
              3.468261756505196e+34, 3.4682617565053744e+34, 3.468261756505316e+34],
             [3.468261756505509e+34, 3.468261756505395e+34, 3.4682617565052974e+34, 3.4682617565053573e+34,
              3.4682617565052425e+34, 3.4682617565056123e+34, 3.4682617565054984e+34],
             [3.4682617565053435e+34, 3.4682617565052826e+34, 3.4682617565053043e+34, 3.4682617565054016e+34,
              3.4682617565054583e+34, 3.468261756505569e+34, 3.468261756505355e+34],
             [3.4682617565052868e+34, 3.468261756505199e+34, 3.4682617565053587e+34, 3.4682617565053024e+34,
              3.4682617565051936e+34, 3.4682617565052374e+34, 3.4682617565053393e+34],
             [3.4682617565052775e+34, 3.4682617565054477e+34, 3.468261756505221e+34, 3.4682617565053287e+34,
              3.4682617565055086e+34, 3.468261756505419e+34, 3.4682617565054357e+34]]
        e = DGHV.generate_public_key(p=p, tau=10)
        c = DGHV.decrypt_full_message(c=a, p=p)
        self.assertIsNotNone(c)
