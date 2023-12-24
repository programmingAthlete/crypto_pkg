from decimal import Decimal
from enum import Enum
from typing import List, Tuple, Union, Dict

from crypto_pkg.ciphers.symmetric.geffe import Geffe
from crypto_pkg.utils.logging import get_logger, set_level

log = get_logger()


def int_2_base_2(k, n):
    r = []
    for i in range(n):
        r.append(k % 2)
        k = k // 2
    return r


def min_check(a, threshold):
    if a > threshold:
        return True
    else:
        return False


def max_check(a, threshold):
    if a < threshold:
        return True
    else:
        return False


class ThresholdsOperator(Enum):
    MIN = min_check
    MAX = max_check


class Attack:

    def __init__(self, all_taps: List[List[int]], n: int, f: List[int], stream_ref: str, max_clock: int):
        """
        Args:
            all_taps: Tabs of the three LFSRs
            n: number of register of each LFSR
            f: function f applied to the output of the three LFSR
            stream_ref: Geffe-like cipher output provided
            max_clock: length of stream_ref
        """
        self.all_taps = all_taps
        self.n = n
        self.f = f
        self.max_iter = 2 ** n - 1
        self.stream_ref = stream_ref
        self.stream_ref_l: List[int] = [int(item) for item in stream_ref]
        self.max_clock = max_clock

    @staticmethod
    def check_match(a1, a2) -> Decimal:
        match = [1 for i in range(len(a1)) if a1[i] == a2[i]]
        return Decimal(sum(match)) / Decimal(len(a1))

    def try_guess(self, g, guess, threshold):
        g.set_state([
            guess,
            0b1010010111010010,
            guess,
        ])
        resp = {0: None, 2: None}
        stream_0 = [g.L[0].clock() for _ in range(self.max_clock)]
        match = self.check_match(a1=self.stream_ref_l, a2=stream_0)
        checked_match0 = threshold[0][0](a=match, threshold=threshold[0][1])
        if checked_match0:
            resp[0] = (guess, match)
        stream_2 = [g.L[2].clock() for _ in range(200)]
        match = self.check_match(a1=self.stream_ref_l, a2=stream_2)
        checked_match2 = threshold[2][0](a=match, threshold=threshold[2][1])
        if checked_match2:
            resp[2] = (guess, match)
        return resp

    def try_guess_for_1(self, g, guess):
        g.set_state([guess[0], guess[1], guess[2]])
        stream_c = [g.clock() for _ in range(self.max_clock)]
        if self.stream_ref_l == stream_c:
            return True, guess
        else:
            return False, None

    def look_for_correlation(self, thresholds: Union[List[Tuple[ThresholdsOperator, float]], None]):

        g = Geffe(self.n, self.all_taps, [1, 1, 0, 1, 0, 0, 0, 1])
        d = [self.try_guess(g=g, threshold=thresholds, guess=i) for i in range(self.max_iter)]
        key0 = [item[0][0] for item in d if item[0] is not None]
        key2 = [item[2][0] for item in d if item[2] is not None]

        return key0, key2

    def find_k1(self, key0, key2) -> Dict[str, list]:
        g = Geffe(self.n, self.all_taps, self.f)
        all_keys = [[k0_item, k1, k2_item] for k0_item in key0 for k1 in range(self.max_iter) for k2_item in
                    key2]
        res = [self.try_guess_for_1(guess=key, g=g) for key in
               all_keys]
        success = [item[1] for item in res if item[0] is True]
        if success:
            result = success[0]
            return {"k0": int_2_base_2(result[0], self.n),
                    "k1": int_2_base_2(result[1], self.n),
                    "k2": int_2_base_2(result[2], self.n)
                    }
        else:
            raise Exception("Attack Failed")

    @set_level(log)
    def attack(self, thresholds, _verbose: bool = False):
        log.info("Search for possible seeds")
        k0, k2 = self.look_for_correlation(thresholds=thresholds)
        log.info("Possible choices for seeds of LFSR 1 and 3")
        msg = f"Possible choices\n\tk_0 = {k0} = {[int_2_base_2(item, 16) for item in k0]}\n" \
              f"\tk_2 = {k2} = {[int_2_base_2(item, 16) for item in k2]}"
        log.debug(msg)
        log.info("Find seed for LFSR 2")
        out = self.find_k1(key0=k0, key2=k2)
        msg = f"\nSuccess\nThe key is (k0,k1,k2)\n\t = {out['k0']},{out['k1']},{out['k2']}"
        log.info(f"{msg}")
        return out


if __name__ == '__main__':
    ''' Example '''

    # Choose Geffe output
    stream = '01001110000011101100011101010111011100000011010001111001101101100000000111110110111011011001010111101100111001111100001111100101110000000010110101001111110110010001111101010110011010010110101011000101'
    # Geffe tabs
    taps = [[0, 1, 4, 7], [0, 1, 7, 11], [0, 2, 3, 5]]
    stream_l = [int(item) for item in stream]
    attack = Attack(all_taps=taps, stream_ref=stream, f=[1, 1, 0, 1, 0, 0, 0, 1], max_clock=200, n=16)

    epsilon_0 = Decimal('0.25')
    epsilon_1 = Decimal('0.25')
    tsh = [(ThresholdsOperator.MAX, Decimal('0.5') - epsilon_0), None,
           (ThresholdsOperator.MIN, Decimal('0.5') + epsilon_1)]

    print(attack.attack(tsh))
