from utils import vec_poly_decompose, vec_poly_HB, vec_poly_MH, sample_poly, CenteredModulo, vec_poly_UH, print_run_time
from poly import polynomial, vector_polynomial, matrix_poly
from hashlib import sha256
from param import *
import pickle

def poly_norm(poly):
    return max([CenteredModulo(poly.f[i], q) for i in range(n)])

def vector_polynomial_norm(vec_poly):
    return max([poly_norm(vec_poly.polynomials[i]) for i in range(vec_poly.l)])

def challenge(M: bytes, w: vector_polynomial):
    tmp = sha256(M + str(w).encode()).digest()
    tmp = bin(int.from_bytes(tmp, 'big'))[2:].ljust(n, '0')
    c = [0] * n
    for i in range(tau):
        if tmp[i] == '1':
            c[i] = 1
        else:
            c[i] = -1
    return polynomial(c)

def wt(h: vector_polynomial):
    count = 0
    for poly in h.polynomials:
        count += poly.f.count(1)
    return count

class Dilithium:
    @print_run_time
    def __init__(self):
        s1 = vector_polynomial([sample_poly(-eta, eta) for _ in range(l)], l)
        s2 = vector_polynomial([sample_poly(-eta, eta) for _ in range(k)], k)
        A = matrix_poly([[sample_poly(0, q) for _ in range(l)] for _ in range(k)], k, l)
        t = A @ s1 + s2
        t1, t0 = vec_poly_decompose(t, 2**d)
        pk = (t1, A)
        sk = (s1, s2, t0)
        self.pk = pk
        self.sk = sk

    @print_run_time
    def sign(self, M: bytes):
        t1, A = self.pk
        s1, s2, t0 = self.sk
        kappa = 0
        z = None
        h = None
        while z == None and h == None:
            y = vector_polynomial([sample_poly(-(gamma1 - 1), gamma1 - 1) for _ in range(l)], l)
            w = A @ y
            w1 = vec_poly_HB(w, 2*gamma2)
            c = challenge(M, w1)
            z = y + c @ s1
            r1, r0 = vec_poly_decompose(w - c@s2, 2*gamma2)

            if vector_polynomial_norm(z) > gamma1 - beta or vector_polynomial_norm(r0) > gamma2 - beta or r1 != w1:
                z = None
                h = None
            else:
                h = vec_poly_MH(-c@t0, w - c@s2 + c@t0, 2*gamma2)
                if vector_polynomial_norm(c@t0) > gamma2 - beta or wt(h) > omega:
                    z = None
                    h = None

            kappa += 1
            # print(kappa)
        sig = (z, h, c)
        return sig

    @print_run_time
    def verify(self, M, sig, pk=None):
        z, h, c = sig
        if pk is None:
            t1, A = self.pk
        else:
            t1, A = pk
        w1_ = vec_poly_UH(h, A@z - c@t1*2**d, 2*gamma2)
        c_ = challenge(M, w1_)
        if c_ == c and vector_polynomial_norm(z) < gamma1 - beta and wt(h) <= omega:
            return True
        else:
            return False

    def save_public_key(self, filename):
        with open(filename, 'wb') as f:
            pickle.dump(self.pk, f)

    @staticmethod
    def load_public_key(filename):
        with open(filename, 'rb') as f:
            return pickle.load(f)
    