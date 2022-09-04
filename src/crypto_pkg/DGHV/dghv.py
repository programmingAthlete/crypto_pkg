from sage import *
from sage.rings.integer_ring import ZZ
from sage.rings.integer import Integer
from sage.misc.prandom import randint, getrandbits
# Python imports
from typing import List, Tuple


class DGHV:

    @staticmethod
    def get_x_i(seed: ZZ, p: ZZ) -> Tuple[ZZ, ZZ]:
        """
        Generate the public key components
        :param seed: seed to generate the pseudo-random number
        :param p: private key
        :return: tuple containing the correction delta and the x_i public key components
        """
        import random
        r = ZZ(getrandbits(71))
        random.seed(int(seed))
        xhi = ZZ(getrandbits(2 * 10 ^ 7))
        delta = xhi - 2 * r
        delta_mod = delta % p
        return delta_mod, xhi - delta_mod

    @classmethod
    def generate_public_key(cls, tau: int, seed: int, p: ZZ) -> int:
        """
        Generate public key
        :param tau: number of components of the public key
        :param seed: seed to generate the pseudo-random numbers
        :param p: private key
        :return: public key
        """
        q0 = ZZ(getrandbits(2 * 10 ^ 5))
        s = q0 * p
        for _ in range(1, tau + 1):
            epsilon_i = randint(0, 1)
            x_i = cls.get_x_i(seed, p)[1]
            s += epsilon_i * x_i
        return s

    @staticmethod
    def encrypt(m: int, e: int) -> Integer:
        """
        Encrypt a bit
        :param m: bit to encrypt
        :param e: public key
        :return:  encrypted bit
        """
        r = ZZ(getrandbits(71))
        return m + 2 * r + e

    @staticmethod
    def decrypt(c: int, p: ZZ) -> Integer:
        """
        Decrypt a bit encryption
        :param c: encrypted bit to decrypt
        :param p:
        :return:
        """
        c_mod = c % p
        return c_mod % 2
