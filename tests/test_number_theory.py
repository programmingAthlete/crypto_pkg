import random
import unittest

from crypto_pkg.contracts.exceptions import CoPrimeException
from crypto_pkg.number_theory.number_theory import NumberTheory


class TestNumberTheory(unittest.TestCase):

    def test_gcd(self):
        """ Test greatest common divisor method """
        resp = NumberTheory.gcd(0, 1)
        self.assertEqual(resp, 1)
        resp = NumberTheory.gcd(2, 6)
        self.assertEqual(resp, 2)
        a = random.randint(1, 10)
        b = random.randint(1, 10)
        self.assertEqual(NumberTheory.gcd(a=a, b=b), NumberTheory.gcd(a=b, b=a))
        self.assertEqual(NumberTheory.gcd(a=15, b=12), 3)

    def test_modular_inverse(self):
        with self.assertRaises(CoPrimeException):
            NumberTheory.modular_inverse(a=2, n=4)
        resp = NumberTheory.modular_inverse(a=5, n=7)
        self.assertEqual(resp, 3)

    def test_chinese_reminder(self):
        with self.assertRaises(CoPrimeException):
            NumberTheory.chinese_reminder(a1=4, n1=2, a2=3, n2=4)
        resp = NumberTheory.chinese_reminder(a1=4, n1=5, a2=3, n2=7)
        self.assertEqual(resp, 28)

    def test_chinese_reminder_list(self):
        with self.assertRaises(CoPrimeException):
            NumberTheory.chinese_reminder_list(a=[1, 2, 3], n=[2, 4, 11])
            NumberTheory.chinese_reminder_list(a=[1, 2, 3], n=[2, 4, 8])
            NumberTheory.chinese_reminder_list(a=[1, 2, 3], n=[1, 4, 8])
            NumberTheory.chinese_reminder_list(a=[1, 2, 3], n=[2, 7, 4])
        resp = NumberTheory.chinese_reminder_list(a=[1, 2, 3], n=[5, 7, 11])
        self.assertEqual(resp, 366)

