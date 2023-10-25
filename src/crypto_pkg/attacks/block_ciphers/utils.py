class Text:
    """
    Number object whose attributes are
        ascii_hex: Hexadecimal ASCII representation
        hex: string with Hexadecimal base representation
        integer: integer number
    """

    def __init__(self, text):
        self.ascii_hex = text
        self.hex = text.hex()
        self.integer = int(text.hex(), 16)


def prepare_key(key: int, max_key=24) -> Text:
    """
    Converts and integer to usable key. Appends 128-max_kex 0 bits after the integer and pads 0 bits before the number
     to satisfy the required number of bits. Then it converts to hexadecimal and instantiate a Text object
    Args:
        key: integer number
        max_key: after max_key bits, a sequence of 0 bits starts

    Returns:
        Text object corresponding to the prepared key.
    """
    try:
        k = bin(key)
        k_n = k[2:] + (128 - max_key) * '0'
        n_k = format(int(k_n, 2), 'x')
        n_k2 = n_k.rjust(2 * 16, '0')
        k_n = bytes.fromhex(n_k2)

    except Exception as exc:
        raise exc
    return Text(text=k_n)