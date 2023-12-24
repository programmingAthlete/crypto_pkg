import logging
from enum import Enum
from logging import getLogger
from multiprocessing import Pool
import random

from crypto_pkg.attacks.block_ciphers.utils import prepare_key
from crypto_pkg.ciphers.symmetric.aes import CustomAES, array_to_matrix, get_array_from_state
from crypto_pkg.utils.logging import set_level, get_logger

log = get_logger(__name__)


class ModifiedAES(CustomAES):

    def aes_round_trans(self, plain_text, round_key=None, last=False):
        state_matrix = array_to_matrix(plain_text)
        # subbytes transformation
        s = self.aes_sub_bytes(state_matrix)
        # mixcolumns transformation
        if last:
            s_k = self.aes_add_round_key(s, round_key)
            return get_array_from_state(s_k)
        else:
            c = self.aes_mix_columns(s)
            s_k = self.aes_add_round_key(c, round_key)
            return get_array_from_state(s_k)

    def encrypt(self, plain_text, key):
        ks = array_to_matrix(key)
        state = array_to_matrix(plain_text)
        s_k = self.aes_add_round_key(state, ks)

        pn = get_array_from_state(s_k)
        for i in range(1, 10):
            tmp = self.aes_round_trans(plain_text=pn, round_key=ks)
            pn = tmp
        pn = self.aes_round_trans(plain_text=pn, round_key=ks, last=True)
        return pn

    def attack_section(self, plain_text, cipher_block_ref, init_pos, section_n=0):
        for i in range(2 ** 32):
            key = prepare_key(i, max_key=init_pos)
            k_block = [int(item, 16) for item in [key.hex[i * 2:i * 2 + 2] for i in range(len(key.hex))] if item != '']
            c = self.encrypt(key=k_block, plain_text=plain_text)
            c_by_block = [c[i * 4:i * 4 + 4] for i in range(len(c))]
            if c_by_block[section_n] == cipher_block_ref[section_n]:
                log.info(f"key guess for block {section_n}: {key.hex}")
                return key

    @set_level(logger=log)
    def attack(self, plain_text: str, cipher_text: str, _verbose: bool = False):
        p_int_list = [int(item, 16) for item in [plain_text[i * 2:i * 2 + 2] for i in range(len(plain_text))] if
                      item != '']
        c_int_list = [int(item, 16) for item in [cipher_text[i * 2:i * 2 + 2] for i in range(len(cipher_text))] if
                      item != '']

        c_by_block_ref = [c_int_list[i * 4:i * 4 + 4] for i in range(len(c_int_list))]
        args = (
            [p_int_list, c_by_block_ref, 32, 0],
            [p_int_list, c_by_block_ref, 64, 1],
            [p_int_list, c_by_block_ref, 96, 2],
            [p_int_list, c_by_block_ref, 128, 3]
        )

        log.debug("Run attack on sub-blocks in parallel")
        with Pool() as pool:
            res = pool.starmap(self.attack_section, args)
        r = [int(item.hex, 16) for item in res]
        log.debug(f"Parallel execution terminated with keys guesses {r}")
        out = r[0] ^ r[1] ^ r[2] ^ r[3]
        log.info(f"128bits key guess: {out}")
        return out


if __name__ == '__main__':
    ''' Example '''

    # ---- Generation of the plain text - cipher text pair
    # Choose the key
    to_find_key = '00000001000000100000000000000a01'
    # Choose a random plain text
    pt = format(random.getrandbits(128), 'x')
    # Prepare plain text and key for encryption
    p = [int(item, 16) for item in [pt[i * 2:i * 2 + 2] for i in range(len(pt))] if item != '']
    k = [int(item, 16) for item in [to_find_key[i * 2:i * 2 + 2] for i in range(len(to_find_key))] if item != '']
    # Generate cipher text
    aes = ModifiedAES()
    c = aes.encrypt(key=k, plain_text=p)
    ct = bytes(c).hex()

    # ---- Run the attack
    log.debug(f"Run the attack with plain-text {p} and cipher-text {p}")
    aes = ModifiedAES()
    result = aes.attack(plain_text=pt, cipher_text=ct, verbose=True)
    assert result == int(to_find_key, 16)
    print(f"\nSuccess: key {to_find_key} recovered")
