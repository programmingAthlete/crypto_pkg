import random
from typing import Dict, Tuple, Union

from Crypto.Cipher import AES

from crypto_pkg.attacks.block_ciphers.utils import Text, prepare_key
from crypto_pkg.utils.logging import get_logger, set_level

log = get_logger(__name__)


class DoubleAESAttack:

    @staticmethod
    def encrypt(key: Text, plain_text: Text) -> Text:
        cipher = AES.new(key.ascii_hex, AES.MODE_ECB)
        cipher_text = cipher.encrypt(plain_text.ascii_hex)
        return Text(text=cipher_text)

    @staticmethod
    def decrypt(key: Text, cipher_text: Text) -> Text:
        cipher = AES.new(key.ascii_hex, AES.MODE_ECB)
        plain_text = cipher.decrypt(cipher_text.ascii_hex)
        return Text(text=plain_text)

    @classmethod
    def lookup_table_computation(cls, plain_text: str, max_key: int = 24) -> Dict[int, int]:
        log.info(f"Compute lookup table for plaintext {plain_text}")
        p = Text(text=bytes.fromhex(plain_text))
        log.debug("Starting lookup table computation")
        out = {cls.encrypt(key=prepare_key(key=i, max_key=max_key), plain_text=p).integer: i for i in
               range(1, 2 ** max_key)}
        log.debug("Lookup table computation completed")
        return out

    @classmethod
    def search_match(cls, cipher_text: str, lookup_table: Dict[int, int]) -> Union[Tuple[Text, Text], None]:
        log.info(f"Search match for ciphertext {cipher_text}")
        c = Text(text=bytes.fromhex(cipher_text))
        for i in range(2 ** 24):
            key = prepare_key(i)
            m = cls.decrypt(key=key, cipher_text=c)
            if lookup_table.get(m.integer):
                log.debug(f"Match found for key {key}")
                return prepare_key(lookup_table.get(m.integer)), key

    @classmethod
    @set_level(logger=log)
    def attack(cls, plain_text: str, cipher_text: str, max_key: int = 24, _verbose: bool = False):
        log.info(f"Constructing encryption lookup table for plain text {plain_text} ans maximum key size {max_key}")
        look_up_table = cls.lookup_table_computation(plain_text=plain_text, max_key=max_key)
        log.info("Search encryption match in lookup table")
        keys = cls.search_match(cipher_text=cipher_text, lookup_table=look_up_table)
        log.debug(f"Key Found")
        return keys


if __name__ == '__main__':

    ''' Example\n
     IMPORTANT NOTICE: faisable with general keys, it still has a complexitx of 2^128.
    In this attack it is assumed that the keys are made of 24bits unknown bits followed by all zero bits.
    '''

    # ---- Generate a plain text - cipher text pair
    # Generate keys
    k1 = prepare_key(random.getrandbits(24))
    k2 = prepare_key(random.getrandbits(24))

    # Generate random plain text
    pt = format(random.getrandbits(128), 'x')

    cipher1 = AES.new(k1.ascii_hex, AES.MODE_ECB)
    c1 = cipher1.encrypt(bytes.fromhex(pt))
    cipher2 = AES.new(k2.ascii_hex, AES.MODE_ECB)
    c2 = cipher2.encrypt(c1)
    print(f"Key k1: {k1.hex}")
    print(f"Key k2: {k2.hex}")

    print("The attack will find back these keys")

    # Suppose that the key is made of 24bits unknown bits followed by all zero bits
    ct = c2.hex()
    print(f'known plain text: {pt}')
    print(f'corresponding cipher text: {ct}')

    print("\nStating the attack")
    print("It might take a bit, but don't worry we'll find it")
    ks = DoubleAESAttack.attack(plain_text=pt, cipher_text=ct, max_key=24)
    if ks:
        print("\nKeys found:")
        print(f"\tk1: 0x{ks[0].hex}")
        print(f"\tk2: 0x{ks[1].hex}")
