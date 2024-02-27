from poly import polynomial, vector_polynomial
from random import randrange
from functools import wraps
from param import *
import time

def CenteredModulo(r, alpha):
    r0 = r % alpha
    if r0 > alpha/2:
        r0 -= alpha
    return r0

def decompose(r, alpha):
    r = r % q
    r0 = CenteredModulo(r, alpha)
    if r - r0 == q - 1:
        r1 = 0
        r0 = r0 - 1
    else:
        r1 = (r - r0) // alpha

    return r1, r0

def poly_decompose(poly, alpha):
    r1 = [0] * n
    r0 = [0] * n
    for i in range(n):
        r1[i], r0[i] = decompose(poly.f[i], alpha)
    return polynomial(r1), polynomial(r0)

def vec_poly_decompose(vec_poly, alpha):
    r1 = [0] * vec_poly.l
    r0 = [0] * vec_poly.l
    for i in range(vec_poly.l):
        r1[i], r0[i] = poly_decompose(vec_poly.polynomials[i], alpha)
    return vector_polynomial(r1, vec_poly.l), vector_polynomial(r0, vec_poly.l)

def HighBits(r, alpha):
    r1, r0 = decompose(r, alpha)
    return r1

def poly_HB(r, alpha):
    r1 = [0] * n
    for i in range(n):
        r1[i] = HighBits(r.f[i], alpha)
    return polynomial(r1)

def vec_poly_HB(r, alpha):
    r1 = [0] * r.l
    for i in range(r.l):
        r1[i] = poly_HB(r.polynomials[i], alpha)
    return vector_polynomial(r1, r.l)

def LowBits(r, alpha):
    r1, r0 = decompose(r, alpha)
    return r0

def MakeHint(u, r, alpha):
    r1 = HighBits(r, alpha)
    v1 = HighBits(u+r, alpha)
    if r1 == v1:
        h = 0
    else:
        h = 1
    return h

def poly_MH(u, r, alpha):
    r1 = poly_HB(r, alpha)
    v1 = poly_HB(u+r, alpha)
    h = [0] * n
    for i in range(n):
        if r1.f[i] == v1.f[i]:
            h[i] = 0
        else:
            h[i] = 1
    return polynomial(h)

def vec_poly_MH(u, r, alpha):
    r1 = vec_poly_HB(r, alpha)
    v1 = vec_poly_HB(u+r, alpha)
    h = [0] * r.l
    for i in range(r.l):
        h[i] = poly_MH(u.polynomials[i], r.polynomials[i], alpha)
    return vector_polynomial(h, r.l)

def UseHint(h, r, alpha):
    m = (q - 1) // alpha
    r1, r0 = decompose(r, alpha)
    if h == 1 and r0 > 0:
        r1 = (r1 + 1) % m
    elif h == 1 and r0 <= 0:
        r1 = (r1 - 1) % m
    else:
        r1 = r1
    return r1

def poly_UH(h, r, alpha):
    m = (q - 1) // alpha
    r1 = [0] * n
    for i in range(n):
        r1[i] = UseHint(h.f[i], r.f[i], alpha)
    return polynomial(r1)

def vec_poly_UH(h, r, alpha):
    m = (q - 1) // alpha
    r1 = [0] * r.l
    for i in range(r.l):
        r1[i] = poly_UH(h.polynomials[i], r.polynomials[i], alpha)
    return vector_polynomial(r1, r.l)

def sample_poly(lower , upper):
    polylist = []
    for i in range(n):
        polylist.append(randrange(lower, upper))
    return polynomial(polylist)

def print_run_time(func):
    @wraps(func)
    def wrapper(*args, **kw):
        start_time = time.time()
        result = func(*args, **kw)
        end_time = time.time()
        print(f"the runing time of {func.__name__} is {end_time - start_time}")
        return result

    return wrapper