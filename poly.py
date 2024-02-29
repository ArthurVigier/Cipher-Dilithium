from param import q, n

class polynomial:
    # polynomial in Zq[x]/<(x^n + 1)>
    def __init__(self, flist):
        if type(flist) == list:
            assert len(flist) == n
            self.f = [flist[i] % q for i in range(n)]

    def __str__(self):
        return str(self.f)

    def __add__(self, other):
        assert type(other) == polynomial
        return polynomial([(self.f[i] + other.f[i]) % q for i in range(n)])
    
    def __sub__(self, other):
        assert type(other) == polynomial
        return polynomial([(self.f[i] - other.f[i]) % q for i in range(n)])

    def __neg__(self):
        neg_coeffs = [(-coeff) % q for coeff in self.f]
        return polynomial(neg_coeffs)
    
    def __mul__(self, other):
        if isinstance(other, int):
            res = [self.f[i] * other % q for i in range(n)]
        elif isinstance(other, polynomial):
            res = [0] * n
            for i in range(n):
                for j in range(n):
                    if i + j < n:
                        res[(i + j)] += self.f[i] * other.f[j]
                        res[(i + j)] %= q
                    else:
                        res[(i + j) % n] += -self.f[i] * other.f[j]
                        res[(i + j) % n] %= q
        else:
            raise TypeError("Unsupported type for * operator")
        return polynomial(res)

    def __matmul__(self, other):
        # Overloaded @ operator for scalar multiplication
        if isinstance(other, vector_polynomial):
            scaled_polys = [self * poly for poly in other.polynomials]
            return vector_polynomial(scaled_polys, other.l)
        else:
            raise TypeError("Unsupported type for @ operator")
    
    def __eq__(self, other):
        if isinstance(other, polynomial):
            return self.f == other.f
        return False

class vector_polynomial:
    # vector polynomial in Zq[x]/<(x^n + 1)> with length l
    def __init__(self, polynomial_list, l):
        assert type(polynomial_list) == list
        assert all(isinstance(poly, polynomial) for poly in polynomial_list)
        self.polynomials = polynomial_list
        self.l = l

    def __str__(self):
        return "[" + ", ".join(str(poly) for poly in self.polynomials) + "]"

    def __add__(self, other):
        assert type(other) == vector_polynomial
        assert self.l == other.l
        sum_polys = [self.polynomials[i] + other.polynomials[i] for i in range(self.l)]
        return vector_polynomial(sum_polys, self.l)

    def __sub__(self, other):
        assert type(other) == vector_polynomial
        assert self.l == other.l
        diff_polys = [self.polynomials[i] - other.polynomials[i] for i in range(self.l)]
        return vector_polynomial(diff_polys, self.l)
    
    def __neg__(self):
        neg_polys = [-poly for poly in self.polynomials]
        return vector_polynomial(neg_polys, self.l)

    def __mul__(self, other):
        if isinstance(other, int):
            res_polys = [poly * other for poly in self.polynomials]
            return vector_polynomial(res_polys, self.l)
        elif isinstance(other, vector_polynomial):
            assert self.l == other.l
            result_poly = polynomial([0] * n)
            for i in range(self.l):
                result_poly += self.polynomials[i] * other.polynomials[i]
        else:
            raise TypeError("Unsupported type for * operator")
        return result_poly

    def __matmul__(self, other):
        if isinstance(other, polynomial):
            scaled_polys = [poly * other for poly in self.polynomials]
            return vector_polynomial(scaled_polys, self.l)
        else:
            raise TypeError("Unsupported type for @ operator")
    
    def __eq__(self, other):
        if isinstance(other, vector_polynomial):
            return self.polynomials == other.polynomials and self.l == other.l
        return False

class matrix_poly:
    def __init__(self, vector_polynomial_list, k, l):
        assert type(vector_polynomial_list) == list
        assert len(vector_polynomial_list) == k
        self.k = k
        self.l = l
        if isinstance(vector_polynomial_list[0], vector_polynomial):
            self.vector_polynomials = vector_polynomial_list
        elif isinstance(vector_polynomial_list[0], list):
            self.vector_polynomials = [vector_polynomial(vector_polynomial_list[i], self.l) for i in range(self.k)]
        
    
    def __matmul__(self, other):
        if isinstance(other, vector_polynomial):
            result_vec_polys = vector_polynomial([self.vector_polynomials[i] * other for i in range(self.k)], self.k)
            return result_vec_polys
        else:
            raise TypeError("Unsupported type for @ operator")