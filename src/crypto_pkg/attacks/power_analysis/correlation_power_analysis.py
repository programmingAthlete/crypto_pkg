import argparse
import logging
import multiprocessing
import os
import time
from multiprocessing import Pool
from typing import Tuple, List
import numpy as np
import pickle

from crypto_pkg.ciphers.symmetric.aes import sbox_table

logging.basicConfig(level=logging.INFO)

log = logging.getLogger(__name__)

log.setLevel(logging.INFO)


def to_hex(n, size=16):
    return hex(n)[2:].zfill(size * 2)


def process_plain_text(text: str) -> List[str]:
    return [item for item in [text[i * 2:i * 2 + 2] for i in range(len(text))] if item != ''][::-1]


def load(filename: str, max_datapoints: int = 4000) -> Tuple[List[List[str]], List[np.ndarray]]:
    """
    Load measurements from the pickle file to the memory

    Args:
        filename: name of the pickle file
        max_datapoints: data point position after which the measurement data wll be ignored
    Returns:
        Tuple(plain texts converted to a list of lists of 16 bytes, processed measurements according to the matrix M)
    """
    if max_datapoints > max_datapoints:
        log.warning(
            "[Attack instantiate] max_datapoint cannot be l40000arger than the numbers of measurement present in the"
            f" pickle file - Setting max_datapoint = {max_datapoints}")
    objects = []
    with (open(filename, "rb")) as openfile:
        while True:
            try:
                objects.append(pickle.load(openfile))
            except EOFError:
                break
    p_texts = [process_plain_text(to_hex(item)) for item in objects[0][0]]
    measures = np.array([item[:max_datapoints] for item in objects[0][1]])
    measurements_processed = [np.array([item[idx] for item in measures]) for idx in range(len(measures[0]))]
    return p_texts, measurements_processed


class Attack:

    def __init__(self, data_filename, max_datapoints):
        plain_texts, measurements = load(filename=data_filename, max_datapoints=max_datapoints)
        self.plain_texts = plain_texts
        self.measurements = measurements

    @staticmethod
    def predictCurrent(keyByte: int, plaintextByte: int) -> int:
        """
        Predict the current consumed from the SBOX(keyByte \oplus plainTextByte) operation. Using the Hamming weight

        Args:
            keyByte: one-byte integer
            plaintextByte: one-byte integer
        Returns:
            Hamming wight of SBOX(keyByte \oplus plainTextByte)
        """
        return bin(sbox_table[keyByte ^ plaintextByte])[2:].count('1')

    @staticmethod
    def calculatePearsonCoefficient(x: np.ndarray, y: np.ndarray) -> float:
        """
        Calculate Pearson Coefficient

        Args:
            x: numpy array
            y: numpy array
        Returns:
            The Pearson Coefficient
        """
        mu_x, mu_y = sum(x) / len(x), sum(y) / len(y)
        z = np.array([(x_item - mu_x) * (y_item - mu_y) for (x_item, y_item) in zip(x, y)])
        z_mean = sum(z) / len(z)
        std_x, std_y = np.sqrt(sum(x ** 2) / len(x) - mu_x ** 2), np.sqrt(sum(y ** 2) / len(y) - mu_y ** 2)
        return z_mean / (std_x * std_y)

    @classmethod
    def generatePredictedCurrents(cls, plain_texts, byte_position: int) -> np.ndarray:
        """
        Generate the matrix P of the predicted currents for all key bytes and plain text bytes

        Args:
            plain_texts: list of list of 16 bytes (each list of 16 bytes being one plain text)
            byte_position: byte position to consider
        Returns:
            Matrix P
        """
        p = np.zeros((2 ** 8, 500))
        for k in range(2 ** 8):
            for i in range(len(plain_texts)):
                b = plain_texts[i][byte_position]
                hexa = int(b, 16)
                p[k][i] = cls.predictCurrent(keyByte=k, plaintextByte=hexa)
        return p

    def computeC(self, predicted_currents: np.ndarray, byte_position: int, save: bool = False) -> np.ndarray:
        """
        Compute the correlation matrix

        Args:
            predicted_currents: predicted currents P
            byte_position: byte position to consider
            save: Save the matrix into a .npy file - Default False
        Returns:
            Correlation matrix C between the measurements and the predicted current
        """
        c = np.zeros((len(predicted_currents), len(self.measurements)))
        for i in range(len(predicted_currents)):
            for j in range(len(self.measurements)):
                c[i][j] = abs(self.calculatePearsonCoefficient(predicted_currents[i], self.measurements[j]))
        if save:
            np.save(f"matrices/matrix_{byte_position}.npy", np.array(c))
        return c

    def attack_byte(self, byte_position: int = 0, plot: bool = False,
                    store: bool = True, re_calculate: bool = False) -> Tuple[int, np.ndarray]:
        """
        Correlation attack of one byte

        Args:
            byte_position: byte position to consider
            plot: show the correlation plot 'byte_position' or not - default = False
            store: save the correlation matrices for the byte 'byte_position' or not - default = True
            re_calculate: re-calculate the correlation matrix for the byte 'byte_position' even it has been stored
        Returns:
            Tuple(byte_position, key byte)
        """
        filename = f"matrices/matrix_{byte_position}.npy"
        if os.path.exists(filename) and not re_calculate:
            log.debug(f"[Process {byte_position}] matrix file {filename} found and -r flag not provided -> reading "
                      f"correlation matrix from file")
            log.info(f"[Process {byte_position}] Reading correlation matrix from file {filename}")
            c = np.load(filename)
        else:
            log.debug(
                f"[Process {byte_position}] Matrix file not found or -r flag provided -> the correlation matrix for the"
                f" byte position {byte_position} is calculated")

            predicted_current_keys = self.generatePredictedCurrents(plain_texts=self.plain_texts,
                                                                    byte_position=byte_position)
            log.debug(f"[Process {byte_position}] Current predicted for all keys")
            log.info(f"[Process {byte_position}] Calculating Correlation matrix C")
            c = self.computeC(save=store, byte_position=byte_position, predicted_currents=predicted_current_keys)
        log.info(f"[Process {byte_position}] Process {byte_position} finished")
        return byte_position, np.unravel_index(np.argmax(c), c.shape)[0]


def full_attack(arguments):
    log.debug("Checking the existence of 'matrices' and 'plot' sub-directories")
    must_have_dirs = ["matrices", "plots"]
    if not os.path.exists(arguments.filename):
        log.error(f"File {arguments.filename} does not exist")
        raise Exception(f"File {arguments.filename} does not exist")
    for item in must_have_dirs:
        if not os.path.exists(item):
            log.warning(f"Directory {item} not found -> creating it")
            os.makedirs(item)
        else:
            log.debug(f"Directory {item} found -> all good")

    print("\nArguments provided")
    args_attr = arguments.__dict__
    for arg in args_attr:
        print(f"\t{arg} -> {args_attr[arg]}")
    print("\n")

    attack = Attack(data_filename=arguments.filename, max_datapoints=arguments.max_datapoint)
    if args.byte_position is not None:
        key_byte = attack.attack_byte(byte_position=arguments.byte_position, plot=arguments.show_plot_correlations,
                                      store=arguments.store_correlation_matrices,
                                      re_calculate=arguments.re_calculate_correlation_matrices)
        print(f"Key byte found: {hex(key_byte[1])[2:]}")
        return

    cores = multiprocessing.cpu_count()
    log.info(f"Number of cores: {cores}. The program wil run in chunks of {cores} byte positions")
    print()

    args_to_processes = tuple(
        [[i, arguments.show_plot_correlations, arguments.store_correlation_matrices,
          arguments.re_calculate_correlation_matrices] for i
         in range(16)])
    log.debug(f"Arguments to the process {args_to_processes}")
    print()

    log.info("Starting the multiprocessing attack")
    ti = time.time()
    with Pool() as pool:
        results = pool.starmap(attack.attack_byte, args_to_processes)
    tf = time.time()
    print()
    log.info(
        f"All processes finished. Final output: {results}. Execution time: {tf - ti} seconds -"
        f" {(tf - ti) / 60} minutes")
    log.debug(f"Constructing the final key from the output")
    out = [(pos, hex(item)[2:]) for (pos, item) in results]
    sorted_list = sorted(out, key=lambda x: x[0])
    key_list = [item[1] for item in sorted_list][::-1]
    key = ''.join(key_list)
    print(f"\nKey Found")
    print(key)
    return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='CorrelationPowerAttack',
        description='Find encryption key via correlation power analysis attack')
    parser.add_argument('-f', '--filename', help="Filename of teh pickle file from where to read the traces", type=str)
    parser.add_argument('-s', '--store_correlation_matrices', help='Store the correlation matrices in a .npy file to '
                                                                   'avoid having to re-ccalculated it at each'
                                                                   ' execution',
                        action='store_true')
    parser.add_argument('--no-store_correlation_matrices', dest='store_correlation_matrices', action='store_false')
    parser.add_argument('-r', '--re_calculate_correlation_matrices', help='Recalculate the correlation matrix',
                        action='store_true')
    parser.add_argument('--no-re_calculate_correlation_matrices', dest='re_calculate_correlation_matrices',
                        action='store_false')
    parser.add_argument('-p', '--show_plot_correlations', help='Show correlation plots - default=False',
                        action='store_true')
    parser.add_argument('--no-show_plot_correlations', dest='show_plot_correlations',
                        action='store_false')
    parser.add_argument('-v', '--verbose', help='Show debug logs', action='store_true')
    parser.add_argument('--no-verbose', help='Show debug logs', action='store_false', dest='verbose')
    parser.add_argument('-l', '--max_datapoint', help='Maximum number of data points to consider - default=3000',
                        type=int)
    parser.add_argument('-b', '--byte_position', type=int,
                        help='Provide the byte position that you want to attack. If this '
                             'argument is provided, the program will only runt he attack for'
                             ' the provided byte position')

    parser.set_defaults(store_correlation_matrices=False, re_calculate_correlation_matrices=False,
                        show_plot_correlations=False, filename="group4.pickle", verbose=False, max_datapoint=4000,
                        byte_position=None)
    args = parser.parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)
    full_attack(arguments=args)
