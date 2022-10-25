from crypto_pkg.contracts.exceptions import KValueException, PrimeNotGeneratedException
from crypto_pkg.contracts.prime_numbers import KBitPrimeResponse, GeneratePrimesResponse
from crypto_pkg.contracts.rsa_scheme import GenerateKeyResponse
from crypto_pkg.number_operations import exp_modular, str_to_int, int_to_str
from crypto_pkg.number_theory.number_theory import NumberTheory
from crypto_pkg.number_theory.prime_numbers import PrimNumbers


class MessageTooBigError(Exception):
    """ Raised when the message is too big """


class RSA:

    def __init__(self, k):
        self.k = k

    def generate_keys(self, p: KBitPrimeResponse, q: KBitPrimeResponse) -> GenerateKeyResponse:
        """
        Generate private and public keys

        :param p: (k/2)-bit prime
        :param q: (k/2)-bit prime
        :return: GenerateKeyResponse(primary, public, modulus)
        """
        phi_n = (p.base_10 - 1) * (q.base_10 - 1)
        e = PrimNumbers.k_bit_prim_number(self.k).base_10
        d = NumberTheory.modular_inverse(e, phi_n) % phi_n
        n = p.base_10 * q.base_10
        return GenerateKeyResponse(private=d, public=e, modulus=n)

    def generate_primes(self, t=100, max_iter=10000) -> GeneratePrimesResponse:
        """
        Generate p and q primes needed for the keys generation

        :param max_iter: maximum possible iterations allowed for succeeding to generate the prime number -
            default max_iter = 10000 to have a high probability of successfully generating the prime number
             for k <= 2000 bits
        :param t: repeat parameter of the Fermat Test
        :return: GeneratePrimesResponse(p, q)
        :raises: KValueException - raised when k is not an even number
        :raises: PrimeNotGeneratedException - raised when the generation of p or q prime number was not successful
        """
        if self.k % 2 != 0:
            print("k must be pair")
            raise KValueException("k must ba an even number")
        p = PrimNumbers.k_bit_prim_number(int(self.k / 2), t=t, max_iter=max_iter)
        q = PrimNumbers.k_bit_prim_number(int(self.k / 2), t=t, max_iter=max_iter)
        # If p and q are the same, continue re-generating q until why are different
        while p.base_10 == q.base_10:
            q = PrimNumbers.k_bit_prim_number(int(self.k / 2), t=t)
        if not p.status or not q.status:
            message = "Primes numbers not generated"
            print(message)
            raise PrimeNotGeneratedException(message)
        return GeneratePrimesResponse(p=p, q=q)

    @staticmethod
    def encrypt_message(message: str, e: int, n: int):
        m = str_to_int(message)
        if m < 0 or m > n - 1:
            raise MessageTooBigError
        return RSA.encrypt(m=m, e=e, n=n)

    @staticmethod
    def decrypt_message(cipher_text: int, d: int, n: int):
        m = RSA.decrypt(c=cipher_text, d=d, n=n)
        return int_to_str(m)

    @staticmethod
    def encrypt(m, e, n):
        """
        Encrypt message

        :param m: plain-text integer element
        :param e: public key key
        :param n: modulus
        :return: integer element of the cipher-text
        """
        return exp_modular(m, e, n)

    @staticmethod
    def decrypt(c: int, d: int, n: int) -> int:
        """
        Decrypt message

        :param c: cipher-text integer element
        :param d: private key
        :param n: modulus
        :return: integer element of the plain-text
        """
        return exp_modular(c, d, n)
