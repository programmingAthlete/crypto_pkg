#! /usr/bin/python
################################################################################
#
# AES-128 encryption. Heavily inspired by http://anh.cs.luc.edu/331/code/aes.py
#
################################################################################

from aes_sbox import SBOX

RCON = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
    0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
    0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
    0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61,
    0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
    0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
    0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
    0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
    0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4,
    0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
    0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
    0xe8, 0xcb
]


def rotate(word):
    return word[1:] + word[:1]


def keyScheduleCore(word, iteration):
    word = rotate(word)
    for i in range(4):
        word[i] = SBOX[word[i]]
    word[0] = word[0] ^ RCON[iteration]
    return word


def expandKey(key):
    currentSize = 0
    rconIteration = 1
    expandedKey = [0] * 176
    for j in range(16):
        expandedKey[j] = key[j]
    currentSize += 16
    while currentSize < 176:
        t = expandedKey[currentSize - 4:currentSize]
        if currentSize % 16 == 0:
            t = keyScheduleCore(t, rconIteration)
            rconIteration += 1
        for m in range(4):
            expandedKey[currentSize] = expandedKey[currentSize - 16] ^ t[m]
            currentSize += 1
    return expandedKey


def addRoundKey(state, roundKey):
    for i in range(16):
        state[i] ^= roundKey[i]
    return state


def createRoundKey(expandedKey, roundKeyPointer):
    roundKey = [0] * 16
    for i in range(4):
        for j in range(4):
            roundKey[j * 4 + i] = expandedKey[roundKeyPointer + i * 4 + j]
    return roundKey


def galois_multiplication(a, b):
    p = 0
    for counter in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        a &= 0xFF
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p


def subBytes(state):
    for i in range(16):
        state[i] = SBOX[state[i]]
    return state


def shiftRow(state, statePointer, nbr):
    for i in range(nbr):
        state[statePointer:statePointer + 4] = state[statePointer + 1:statePointer + 4] + state[
                                                                                          statePointer:statePointer + 1]
    return state


def shiftRows(state):
    for i in range(4):
        state = shiftRow(state, i * 4, i)
    return state


def mixColumn(column):
    mult = [2, 1, 1, 3]
    cpy = list(column)
    g = galois_multiplication
    column[0] = g(cpy[0], 2) ^ g(cpy[3], 1) ^ g(cpy[2], 1) ^ g(cpy[1], 3)
    column[1] = g(cpy[1], 2) ^ g(cpy[0], 1) ^ g(cpy[3], 1) ^ g(cpy[2], 3)
    column[2] = g(cpy[2], 2) ^ g(cpy[1], 1) ^ g(cpy[0], 1) ^ g(cpy[3], 3)
    column[3] = g(cpy[3], 2) ^ g(cpy[2], 1) ^ g(cpy[1], 1) ^ g(cpy[0], 3)
    return column


def mixColumns(state):
    for i in range(4):
        column = state[i:i + 16:4]
        column = mixColumn(column)
        state[i:i + 16:4] = column
    return state


def aes_round(state, roundKey):
    state = subBytes(state)
    state = shiftRows(state)
    state = mixColumns(state)
    state = addRoundKey(state, roundKey)
    return state


def aes_main(state, expandedKey):
    state = addRoundKey(state, createRoundKey(expandedKey, 0))
    i = 1
    while i < 10:
        state = aes_round(state, createRoundKey(expandedKey, 16 * i))
        i += 1
    state = subBytes(state)
    state = shiftRows(state)
    state = addRoundKey(state, createRoundKey(expandedKey, 160))
    return state


def intToArray(x):
    return [(x >> (i * 8)) & 0xff for i in range(16)]


def arrayToInt(a):
    x = 0
    for i, e in enumerate(a):
        x += (e << (8 * i))
    return x


def encrypt(iput, key):
    output = [0] * 16
    block = [0] * 16
    expandedKeySize = 176
    p = intToArray(iput)
    for i in range(4):
        for j in range(4):
            block[(i + (j * 4))] = p[(i * 4) + j]
    expandedKey = expandKey(intToArray(key))
    block = aes_main(block, expandedKey)
    for k in range(4):
        for l in range(4):
            output[(k * 4) + l] = block[(k + (l * 4))]
    return arrayToInt(output)


if __name__ == "__main__":
    p = 0x0123456789abcdefabcdef0123456789
    k = 0x9310cd51c2a398b380845768793530f5
    c = encrypt(p, k)
    print("c = 0x%032x =>" % c)
    if c == 0xe9fb48cb64242bb2bf9c681cd023de0b:
        print("OK")
    else:
        print("ERROR!")
