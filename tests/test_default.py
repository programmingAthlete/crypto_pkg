import unittest

from crypto_pkg.defaut import default


class TestDefault(unittest.TestCase):

    def test_default(self):
        f = default()
        self.assertEqual(f, True)
