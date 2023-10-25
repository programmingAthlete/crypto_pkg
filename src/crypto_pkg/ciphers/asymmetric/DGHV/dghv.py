from typing import List, Tuple
import random

from crypto_pkg.number_operations import int_2_base, base_to_10


class DGHV:

    @staticmethod
    def get_x_i(p) -> Tuple[int, int]:
        """
        Generate the public key components
        :param p: private key
        :return: tuple containing the correction delta and the x_i public key components
        """
        import random
        r = random.getrandbits(71)
        xhi = random.getrandbits(2 * 10 ^ 7)
        delta = xhi - 2 * r
        delta_mod = delta % p
        return delta_mod, xhi - delta_mod

    @classmethod
    def generate_public_key(cls, tau: int, p: int) -> int:
        """
        Generate public key
        :param tau: number of components of the public key
        :param p: private key
        :return: public key
        """
        q0 = random.getrandbits(2 * 10 ^ 5)
        s = q0 * p
        for _ in range(1, tau + 1):
            epsilon_i = random.randint(0, 1)
            x_i = cls.get_x_i(p)[1]
            s += epsilon_i * x_i
        return s

    @staticmethod
    def encrypt(m: int, e: int) -> int:
        """
        Encrypt a bit
        :param m: bit to encrypt
        :param e: public key
        :return:  encrypted bit
        """
        r = random.getrandbits(71)
        return m + 2 * r + e

    @staticmethod
    def decrypt(c: int, p: int) -> int:
        """
        Decrypt a bit encryption
        :param c: encrypted bit to decrypt
        :param p:
        :return:
        """
        c_mod = c % p
        return c_mod % 2

    @staticmethod
    def str_to_bin(message: str) -> List[List[int]]:
        """
        Convert string message to list of binary characters
            (list of lists - the binary of a character is the list of bits)
        :param message: string message
        :return: list of binaries
        """
        ascii_decimal = [ord(item) for item in message]
        return [int_2_base(item, 2) for item in ascii_decimal]

    @classmethod
    def encrypt_full_message(cls, message: str, e: int) -> List[List[int]]:
        """
        Encrypt the message to a list of lists containing the encryption of each bit
        :param e: public key
        :param message: message to encrypt
        :return: list of lists containing the encryption of each bit of the characters of the message
            (list of lists - each sublist represent the encryption of the bits of a character)
        """
        bin_message = cls.str_to_bin(message=message)
        return [[cls.encrypt(m=binary, e=e) for binary in binaries] for binaries in bin_message]

    @staticmethod
    def ascii_numer_to_str(number: List[int]) -> List[str]:
        """
        Convert ascii number to string
        :param number: list of numbers of Ascii characters
        :return: list of Ascii characters
        """
        return [chr(int(item)) for item in number]

    @classmethod
    def decrypt_full_message(cls, c: list, p: int) -> str:
        """
        Decrypt message numeric cipher-text to string message

        :param c:
        :param p:
        :return: decrypted string message
        """
        decrypted_bins = [[cls.decrypt(c=int(c_bit), p=p) for c_bit in encrypted_bits] for encrypted_bits in c]
        decrypted_base_10 = [base_to_10(numb=item, base=2) for item in decrypted_bins]
        return ''.join(cls.ascii_numer_to_str(decrypted_base_10))
