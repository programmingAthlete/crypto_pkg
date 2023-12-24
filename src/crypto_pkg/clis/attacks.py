import os
from decimal import Decimal
import random
from typing import Optional

import typer
from Crypto.Cipher import AES

from crypto_pkg.attacks.block_ciphers.double_encryption import DoubleAESAttack
from crypto_pkg.attacks.block_ciphers.modified_aes import ModifiedAES
from crypto_pkg.attacks.block_ciphers.utils import prepare_key
from crypto_pkg.attacks.power_analysis.correlation_power_analysis import Attack as PowerAnalysisAttack
from crypto_pkg.attacks.stream_ciphers.geffe_cipher import Attack as GeffeAttack, ThresholdsOperator
from crypto_pkg.contracts.cli_dto import ModifiedAESIn
from importlib import resources

app = typer.Typer(pretty_exceptions_show_locals=False, no_args_is_help=True)


def get_hex(x):
    return '{:02x}'.format(x).zfill(32)


@app.command('geffe')
def attack_geffe(
        verbose: bool = typer.Option(False, help="Show debug logs")
):
    """
    Example on how to use the attack on a Geffe stream cipher.\n
    The function doesn't tae any argument, the stream of the cipher is hardcoded together with the LSFRs
    settings
     """
    # Choose Geffe output
    stream = '01001110000011101100011101010111011100000011010001111001101101100000000111110110111011011001010111101100111001111100001111100101110000000010110101001111110110010001111101010110011010010110101011000101'
    # Geffe tabs
    taps = [[0, 1, 4, 7], [0, 1, 7, 11], [0, 2, 3, 5]]
    attack = GeffeAttack(all_taps=taps, stream_ref=stream, f=[1, 1, 0, 1, 0, 0, 0, 1], max_clock=200, n=16)

    epsilon_0 = Decimal('0.25')
    epsilon_1 = Decimal('0.25')
    tsh = [(ThresholdsOperator.MAX, Decimal('0.5') - epsilon_0), None,
           (ThresholdsOperator.MIN, Decimal('0.5') + epsilon_1)]

    attack.attack(thresholds=tsh, _verbose=verbose)


@app.command("modifiedAES")
def attack_modifier_aes(
        plain_text: Optional[str] = typer.Option(None, help="128bits plain text to encrypt"),
        cipher_text: Optional[str] = typer.Option(None, help="128bits encryption of the plain_text"),
        key: Optional[str] = typer.Option(None, help="Encryption 128bits key to Find"),
        verbose: bool = typer.Option(False, help="Show debug logs")
):
    """
    Example on how to use the attack on the modified AES.\n
    If no arguments are provided, an hardcoded key will be used is such a way that the execution is not long, a plain
    text will be generated at random and the corresponding cipher text will be generated using the hardcoded key.
    After this the attack will recover the key from the (plain text, cipher text) pair.\n
    If the plain_text is provided, the key hardcoded key will be used to generate the (plain text, cipher text pair)
    and then recovered.\n
    If the plain text and the cipher text are provided, the encryption key corresponding to the pait will be recovered.
    This operation might take a bit of time depending on the key.
    """
    model = ModifiedAESIn(key=key, plain_text=plain_text, cipher_text=cipher_text)

    if all(item is None for item in [model.key, model.plain_text, model.cipher_text]):
        # ---- Generation of the plain text - cipher text pair
        # Choose the key
        model.key = '00000001000000100000000000000a01'
        # Choose a random plain text
        model.plain_text = format(random.getrandbits(128), 'x')
        # Prepare plain text and key for encryption
        p = [int(item, 16) for item in [model.plain_text[i * 2:i * 2 + 2] for i in range(len(model.plain_text))] if
             item != '']
        k = [int(item, 16) for item in [model.key[i * 2:i * 2 + 2] for i in range(len(model.key))] if item != '']
        # Generate cipher text
        aes = ModifiedAES()
        c = aes.encrypt(key=k, plain_text=p)
        ct = bytes(c).hex()
    elif model.plain_text is not None and model.cipher_text is not None:
        model.plain_text = plain_text
        ct = cipher_text
        p = [int(item, 16) for item in [model.plain_text[i * 2:i * 2 + 2] for i in range(len(model.plain_text))] if
             item != '']
    elif model.plain_text is not None and model.cipher_text is None and model.key is not None:
        model.plain_text = plain_text
        aes = ModifiedAES()
        k = [int(item, 16) for item in [key[i * 2:i * 2 + 2] for i in range(len(key))] if item != '']
        ct = bytes(aes.encrypt(key=k, plain_text=model.plain_text)).hex()
        p = [int(item, 16) for item in [model.plain_text[i * 2:i * 2 + 2] for i in range(len(model.plain_text))] if
             item != '']
    else:
        raise Exception("Parameters not provided correctly - if plain text is provided, ")

    # ---- Run the attack
    print(f"Run the attack with plain-text {p} and cipher-text {p}")
    aes = ModifiedAES()
    result = aes.attack(plain_text=model.plain_text, cipher_text=ct, _verbose=verbose)
    if model.key is not None:
        # Check that the key is the one provided
        assert result == int(model.key, 16)
        k_hex = get_hex(result)
        k = [int(item, 16) for item in [k_hex[i * 2:i * 2 + 2] for i in range(len(k_hex))] if item != '']
        p = [int(item, 16) for item in [model.plain_text[i * 2:i * 2 + 2] for i in range(len(model.plain_text))] if
             item != '']
        c = aes.encrypt(key=k, plain_text=p)
        assert bytes(c).hex() == ct
    else:
        # Re-encrypt the plain text to validate the key
        aes = ModifiedAES()
        k_hex = get_hex(result)
        k = [int(item, 16) for item in [k_hex[i * 2:i * 2 + 2] for i in range(len(k_hex))] if item != '']
        p = [int(item, 16) for item in [model.plain_text[i * 2:i * 2 + 2] for i in range(len(model.plain_text))] if
             item != '']
        c = bytes(aes.encrypt(key=k, plain_text=p)).hex()
        assert c == ct
    print(f"\nSuccess: key {result} recovered")


@app.command("AES-double-encryption")
def attack_double_encryption(
        plain_text: Optional[str] = typer.Option(None, help="128bits plain text to encrypt"),
        cipher_text: Optional[str] = typer.Option(None, help="128bits encryption of the plain_text"),
        verbose: Optional[bool] = typer.Option(False, help="Show debug logs"),
):
    """
    Example on how to use the double encryption attack on AES.\n
    If no arguments are provided, the two keys and a plain text will be generated to create the
     (plain text, cipher text) pair. Then the key will be recovered
    If the plain text and the cipher text are provided, they will be used as (plain text, cipher text) par.
    IMPORTANT NOTICE: Make sure that the pair you provide are generated with faisable keys: this attack is not
    faisable with general keys, it still has a complexitx of 2^128.
    In this attack it is assumed that the keys are made of 24bits unknown bits followed by all zero bits.
    """

    if plain_text is None and cipher_text is None:
        # ---- Generate a plain text - cipher text pair
        # Suppose that the keys is made of 24bits unknown bits followed by all zero bits

        # Generate keys
        k1 = prepare_key(random.getrandbits(24))
        k2 = prepare_key(random.getrandbits(24))

        # Generate random plain text
        pt = format(random.getrandbits(128), 'x')

        cipher1 = AES.new(k1.ascii_hex, AES.MODE_ECB)
        c1 = cipher1.encrypt(bytes.fromhex(pt))
        cipher2 = AES.new(k2.ascii_hex, AES.MODE_ECB)
        c2 = cipher2.encrypt(c1)
        ct = c2.hex()
        print(f"Key k1: {k1.hex}")
        print(f"Key k2: {k2.hex}")
        print("The attack will find back these keys")
    else:
        ct = cipher_text
        pt = plain_text

    print(f'known plain text: {pt}')
    print(f'corresponding cipher text: {ct}')

    print("\nStating the attack")
    print("It might take a bit, but don't worry we'll find it")
    ks = DoubleAESAttack.attack(plain_text=pt, cipher_text=ct, max_key=24, _verbose=verbose)
    if ks:
        print("\nKeys found:")
        print(f"\tk1: 0x{ks[0].hex}")
        print(f"\tk2: 0x{ks[1].hex}")


@app.command("correlation-power-analysis")
def attack_correlation_power_analysis(
        filename: str = typer.Argument('test_file.pickle',
                                       help="Filename of the pickle file with the measurements"),
        max_datapoints: Optional[int] = typer.Option(400, help="Maximum number of data points to consider"),
        byte_position: Optional[int] = typer.Option(None, help="Byte position to attack"),
        verbose: Optional[bool] = typer.Option(None, help="Show debug logs")
):
    """
    Example on how to use the power correlation attack.\n
    The filename of the measurement file is required. This file mush be a valid pickle file with at leas 'max_datapoints'
     datapoints\n
    If a byte position is provided, only the provided key byte will be attacked, otherwise the whole key will be.
    """
    with resources.open_binary('crypto_pkg.attacks.power_analysis', 'test_file.pickle') as file:
        content = file.read()

    with open(filename, 'wb') as f:
        f.write(content)
    if not os.path.exists(filename):
        msg = f"File {filename} does not exist"
        print(msg)
        raise Exception(f"File {msg}")

    # Run the correlation attack on the provided byte position
    attack = PowerAnalysisAttack(data_filename=filename, max_datapoints=max_datapoints)
    if byte_position is not None:
        key_byte = attack.attack_byte(byte_position=byte_position, plot=False,
                                      store=False,
                                      re_calculate=True, _verbose=verbose)
        print(f"Key byte found: {hex(key_byte[1])[2:]}")
    else:
        key = attack.attack_full_key(store_correlation_matrices=False, re_calculate_correlation_matrices=False,
                                     show_plot_correlations=False, _verbose=verbose)
        print("Key Found")
        print(key)
    os.remove(filename)
