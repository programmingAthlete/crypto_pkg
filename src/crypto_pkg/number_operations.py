import math


def int_2_base(a: int, base: int) -> list:
    """
    Convert integer to base "base"

    :param a: integer to convert to big number form in base "base"
    :param base: base into which to convert integer "a"
    :return: bin number form in base "base" corresponding to "a"
    """
    x = a
    reminders = []
    while x != 0:
        q = x // base
        r = x % base
        x = q
        reminders.append(r)
    return reminders[::-1]


def exp_modular(a: int, exponent: int, n: int) -> int:
    """
    Modular exponentiation

    :param a: number to exponentiate
    :param exponent: exponent
    :param n: modulus
    :return: a^exponent (mod n)
    """
    exp = int_2_base(exponent, 2)
    c = a
    for i in range(1, len(exp)):
        c = c * c % n
        if exp[i] == 1:
            c = c * a % n
    return c


def base_to_10(numb: [int], base: int) -> int:
    """
    Convert number from base "base" to base 10 integer

    :param numb: number in big number form in base "base" in [a_k,a_{k-1},..a_1,a_0] form
    :param base: base in which "numb" is written
    :return: integer corresponding to the base 10 of "numb"
    """
    base_10 = 0
    for i in range(len(numb)):
        base_10 += numb[::-1][i] * base ** i
    return base_10


def str_to_int(s: str) -> int:
    return int.from_bytes(s.encode(), byteorder='little')


def int_to_str(i: int) -> str:
    length = math.ceil(i.bit_length() / 8)
    return i.to_bytes(length, byteorder='little').decode()
