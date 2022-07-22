from random import randint

from crypto_pkg.contracts.prime_numbers import KBitPrimeResponse
from crypto_pkg.number_operations import base_to_10, exp_modular


class PrimNumbers:

    @staticmethod
    def k_bit_numer(k: int):
        """
        Generate an iterator object of k bits with the first bit being 1 (starting with the first bit being 0 is like
         having a k-1 bit number) and other k-1 random bits.

        :param k: length of the iterator to return
        """
        if k > 1:
            yield 1
        for _ in range(k - 1):
            yield randint(0, 1)

    @staticmethod
    def fermat_test(n: int, t=100) -> bool:
        """
        Fermat Test - test if a number is prime

        :param t: repeat parameter of the Fermat Test
        :param n: numbers to test
        :return: True if n is prime and False if it isn't prime
        """
        for _ in range(t):
            a = randint(2, n - 2)
            r = exp_modular(a, n - 1, n)
            if r != 1:
                return False
        return True

    @classmethod
    def k_bit_prim_number(cls, k, t=100, max_iter=10000):
        """
        Generate a k-bit prime number

        :param k: length of bit of the prime number to generate
        :param t: repeat parameter of the Fermat Test
        :param max_iter: maximum possible iterations allowed for succeeding to generate the prime number -
            default max_iter = 10000 to have a high probability of successfully generating the prime number
             for k <= 2000 bits
        :return: KBitPrimeResponse(status: bool, base_10: int, base_2: list)
        """
        i = 0
        while i < max_iter:
            k_bit_n = list(cls.k_bit_numer(k))
            base_10_n = base_to_10(k_bit_n, 2)
            response = cls.fermat_test(n=base_10_n, t=t)
            if response:
                return KBitPrimeResponse(status=True, base_10=base_10_n, base_2=k_bit_n)
            i += 1
        return KBitPrimeResponse(status=False, base_10=None, base_2=[])