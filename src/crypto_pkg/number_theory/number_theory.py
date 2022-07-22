from itertools import combinations, permutations

from crypto_pkg.contracts.exceptions import CoPrimeException


class NumberTheory:

    @staticmethod
    def gcd(a, b):
        """
        Euclidian algorithm to find the Greatest Common Divisor

        :param a:
        :param b:
        :return: gcd of a and b
        """
        r = a % b
        while r != 0:
            x = b
            b = r
            r = x % b
        return b

    @classmethod
    def modular_inverse(cls, a: int, n: int) -> int:
        """
        Modular inverse of a in modulo n.
        Find u such that a * u + n * v = 1

        :param a: integer of which to calculate the modular inverse
        :param n: modulus
        :return: modular inverse of a in modulo n
        :raises: CoPrimeException a and n are not co-primes
        """
        if cls.gcd(a, n) != 1:
            raise CoPrimeException(f"{a} and {n} are not co-primes")
        r_list = [a, n]
        u = [1, 0]
        v = [0, 1]
        while r_list[-1] != 0:
            q = r_list[0] // r_list[1]
            u_value = u[0] - q * u[1]
            v_value = v[0] - q * v[1]
            u = [u[1], u_value]
            v = [v[1], v_value]
            r = r_list[0] % r_list[1]
            r_list = [r_list[1], r]
        return u[-2]

    @classmethod
    def chinese_reminder(cls, a1: int, n1: int, a2: int, n2: int) -> int:
        """
        Chinese reminder.
        Compute z as n2 * m1 * a1 + n1 * m2 * a2, where m1 and m2 are the modular inverses of n1 and n2 respectively
        in such a way to have z = a1 (mod n1) and z = a2 (mod n2)

        :param a1: integer a1
        :param n1: modulus n1
        :param a2: integer a2
        :param n2: modulus n2
        :return: chinese reminder of a1,n1,a2,n2
        :raises: CoPrimeException if the two modulus ar not co-primes
        """
        if cls.gcd(n1, n2) != 1:
            raise CoPrimeException(f"{n1} and {n2} are not co-primes")
        n1_inv = cls.modular_inverse(n2, n1)
        n2_inv = cls.modular_inverse(n1, n2)
        z = n2 * n1_inv * a1 + n1 * n2_inv * a2
        return z % n1 * n2

    @classmethod
    def chinese_reminder_list(cls, a: [int], n: [int]) -> int:
        """
        Chinese reminder from a list of integers as and list of modulus ns.
        we want to have z such that z = a_i (mod n_i), we hence compute it as
        z = \sum_i^{len(a)} ( \prod_{j \neq i} (n_j * m_j * a_i) )

        :param a: list of integers as
        :param n: list of modulus ns
        :return: chinese reminder of as in modulus ns
        :raises: CoPrimeException if the modulus ar not co-primes
        """
        comb = list(combinations(n, 2))
        if any(cls.gcd(*item) != 1 for item in comb):
            raise CoPrimeException("The modulus are not two by two co-primes")
        mod = 1
        for item in n:
            mod *= item
        permutations_list = list(permutations(n, 2))
        z = 0
        for i in range(len(a)):
            p = a[i]
            for j in range(len(permutations_list)):
                if n[i] == permutations_list[j][1]:
                    p *= cls.modular_inverse(*permutations_list[j]) * permutations_list[j][0]
            z += p
        res = z % mod
        return res
