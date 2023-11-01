from random import randint


class LFSR:
    def __init__(self, n, taps):
        self.n = n

        self.taps = tuple(taps)
        assert self.taps[0] == 0
        assert 0 <= min(self.taps) <= max(self.taps) <= n - 1

        self.state = (0,) * n

    def init(self, state):
        assert len(state) == self.n
        self.state = tuple(state)

    def init_random(self):
        self.state = tuple(randint(0, 1) for _ in range(self.n))

    def clock(self):
        output = self.state[0]
        new_val = 0
        for t in self.taps:
            new_val ^= self.state[t]
        self.state = self.state[1:] + (new_val,)
        return output

    def filter(self, eq):
        output = 0
        for monomial in eq:
            monomial_value = 1
            for varindex in monomial:
                monomial_value &= self.state[varindex]
            output ^= monomial_value
        return output

    def __str__(self):
        output = ""
        for i in reversed(range(0, self.n)):
            output += str(self.state[i])
        return output


class Geffe:
    def __init__(self, n, all_taps, F):
        assert len(all_taps) == 3
        # assert len(F) == 8
        self.L = [LFSR(n, taps) for taps in all_taps]
        self.n = n
        self.F = F

    def set_state(self, k):
        states = [[], [], []]
        for i in range(self.n):
            for s in range(3):
                states[s].append(k[s] % 2)
                k[s] = k[s] // 2

        for s in range(3):
            self.L[s].init(states[s])

    def clock(self):
        f_input = 0
        for s in range(3):
            f_input = (f_input << 1) | (self.L[s].clock())
        return self.F[f_input]

    def __str__(self):
        output = ""
        for s in range(3):
            output += str(self.L[s]) + " "
        return output[:-1]
