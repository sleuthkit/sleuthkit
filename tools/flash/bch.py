"""Systematic, MSB-first shortened binary BCH decoder.

Adapted from Gerd1986/qnxprobe qualcomm_kombox.py (MIT).
Correction is accepted only after every syndrome verifies again.
"""


class BCH:
    def __init__(self, m, t, primitive_polynomial):
        if not 5 <= m <= 16 or not 1 <= t <= 16:
            raise ValueError('supported BCH: m=5..16, t=1..16')
        if primitive_polynomial.bit_length() != m+1 or not primitive_polynomial & 1:
            raise ValueError('invalid primitive polynomial degree/constant term')
        self.m, self.t, self.n = m, t, (1 << m)-1
        roots = set()
        for i in range(1, 2*t+1):
            j = i % self.n
            while j not in roots:
                roots.add(j)
                j = (2*j) % self.n
        if len(roots) % 8:
            raise ValueError('BCH parity degree must be byte-aligned; parity padding is not implemented')
        self.ecc_bytes = len(roots)//8
        self.exp = [0]*(2*self.n)
        self.log = [-1]*(1 << m)
        x = 1
        for i in range(self.n):
            if self.log[x] != -1:
                raise ValueError('polynomial is not primitive for this field')
            self.exp[i], self.log[x] = x, i
            x <<= 1
            if x & (1 << m):
                x ^= primitive_polynomial
        if x != 1:
            raise ValueError('invalid field cycle')
        self.exp[self.n:] = self.exp[:self.n]
        self.odd = tuple(range(1, 2*t, 2))
        self.fast_mul, self.fast_byte = {}, {}
        for j in self.odd:
            a = self.exp[j % self.n]
            a8 = 1
            for _ in range(8):
                a8 = self.mul(a8, a)
            self.fast_mul[j] = [self.mul(v, a8) for v in range(1 << m)]
            values = []
            for byte in range(256):
                value = 0
                for k in range(7, -1, -1):
                    value = self.mul(value, a) ^ ((byte >> k) & 1)
                values.append(value)
            self.fast_byte[j] = values

    def mul(self, a, b):
        return 0 if not a or not b else self.exp[(self.log[a]+self.log[b]) % self.n]

    def syndromes(self, code):
        values = {}
        for j in self.odd:
            value = 0
            mt, bt = self.fast_mul[j], self.fast_byte[j]
            for byte in code:
                value = mt[value] ^ bt[byte]
            values[j] = value
        for j in range(2, 2*self.t+1, 2):
            values[j] = self.mul(values[j//2], values[j//2])
        return [values[j] for j in range(1, 2*self.t+1)]

    def locator(self, syndromes):
        c, b = [0]*(2*self.t+1), [0]*(2*self.t+1)
        c[0] = b[0] = 1
        degree, shift, previous = 0, 1, 1
        for n in range(2*self.t):
            delta = syndromes[n]
            for i in range(1, degree+1):
                if c[i] and syndromes[n-i]:
                    delta ^= self.mul(c[i], syndromes[n-i])
            if not delta:
                shift += 1
                continue
            coefficient = self.exp[(self.log[delta]-self.log[previous]) % self.n]
            old = c[:]
            for j in range(2*self.t+1-shift):
                if b[j]:
                    c[j+shift] ^= self.mul(coefficient, b[j])
            if 2*degree <= n:
                degree, b, previous, shift = n+1-degree, old, delta, 1
            else:
                shift += 1
        return c, degree

    def correct(self, payload, ecc):
        if len(ecc) != self.ecc_bytes or (len(payload)+len(ecc))*8 > self.n:
            raise ValueError('codeword length does not fit this BCH profile')
        code = bytearray(payload+ecc)
        syndromes = self.syndromes(code)
        if not any(syndromes):
            return bytes(payload), 0, 'clean'
        loc, degree = self.locator(syndromes)
        if not 1 <= degree <= self.t:
            return bytes(payload), 0, 'uncorrectable'
        positions = []
        for p in range(len(code)*8):
            z = self.exp[(self.n-p) % self.n]
            value, power = 0, 1
            for coefficient in loc[:degree+1]:
                if coefficient:
                    value ^= self.mul(coefficient, power)
                power = self.mul(power, z)
            if not value:
                positions.append(p)
        if len(positions) != degree:
            return bytes(payload), 0, 'uncorrectable'
        for p in positions:
            left = len(code)*8-1-p
            code[left//8] ^= 1 << (7-left % 8)
        if any(self.syndromes(code)):
            return bytes(payload), 0, 'uncorrectable'
        return bytes(code[:len(payload)]), len(positions), 'corrected'
