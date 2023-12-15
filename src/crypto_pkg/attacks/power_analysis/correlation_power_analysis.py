import logging
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


if __name__ == '__main__':
    filename = "test_file_name.pickle"
    # Run the full correlation attack
    attack = Attack(data_filename=filename, max_datapoints=400)
    args_to_processes = tuple(
        [[i, False, False, True] for i
         in range(16)])

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
