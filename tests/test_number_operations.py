import unittest

from crypto_pkg.number_operations import str_to_int, int_to_str


class TestNumberOperations(unittest.TestCase):

    def test_string_to_int(self):
        message = "convert this string"
        integer = str_to_int(message)
        m = int_to_str(integer)
        self.assertEqual(message, m)
