from typing import Dict, Tuple, Union

from Crypto.Cipher import AES

from crypto_pkg.attacks.block_ciphers.utils import Text, prepare_key


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
        p = Text(text=bytes.fromhex(plain_text))
        out = {cls.encrypt(key=prepare_key(key=i, max_key=max_key), plain_text=p).integer: i for i in
               range(1, 2 ** max_key)}
        return out

    @classmethod
    def search_match(cls, cipher_text: str, lookup_table: Dict[int, int]) -> Union[Tuple[Text, Text], None]:
        c = Text(text=bytes.fromhex(cipher_text))

        for i in range(2 ** 24):
            key = prepare_key(i)
            m = cls.decrypt(key=key, cipher_text=c)
            if lookup_table.get(m.integer):
                return prepare_key(lookup_table.get(m.integer)), key

    @classmethod
    def attack(cls, plain_text: str, cipher_text: str, max_key: int = 24):
        look_up_table = cls.lookup_table_computation(plain_text=plain_text, max_key=max_key)
        keys = cls.search_match(cipher_text=cipher_text, lookup_table=look_up_table)
        return keys


if __name__ == '__main__':

    ''' Example '''

    # Suppose that the key is made of 24bits unknown bits followed by all zero bits
    pt = '2355502c48059b15f70ddf4938b3b97e'
    ct = '5d64800bce91edda9c3bad2956be5b12'
    print(f'known plain text: {pt}')
    print(f'corresponding cipher text: {ct}')

    print("\nStating the attack")
    print("It might take a bit, but don't worry we'll find it")
    ks = DoubleAESAttack.attack(plain_text=pt, cipher_text=ct, max_key=24)
    if ks:
        print("\nKeys found:")
        print(f"\tk1: 0x{ks[0].hex}")
        print(f"\tk2: 0x{ks[1].hex}")
