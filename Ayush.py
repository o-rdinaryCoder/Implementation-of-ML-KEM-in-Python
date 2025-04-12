import numpy as np
import secrets
import hashlib

# Parameters
N = 4  # Polynomial degree
Q = 3329  # A prime modulus
K = 2  # Matrix dimension

def poly_add(a, b):
    """Add two polynomials modulo Q."""
    return [(x + y) % Q for x, y in zip(a, b)]

def poly_sub(a, b):
    """Subtract two polynomials modulo Q."""
    return [(x - y) % Q for x, y in zip(a, b)]

def poly_mul(a, b):
    """Multiply two polynomials modulo X^N + 1 and Q."""
    res = [0] * (2 * N - 1)
    for i in range(N):
        for j in range(N):
            res[i + j] += a[i] * b[j]
    # Reduce mod X^N + 1
    for i in range(N, 2 * N - 1):
        res[i - N] = (res[i - N] - res[i]) % Q
    return [x % Q for x in res[:N]]

def gen_poly():
    """Generate a random polynomial with very small coefficients."""
    return [secrets.randbelow(3) - 1 for _ in range(N)]  # Coefficients in {-1, 0, 1}

def gen_matrix(k):
    """Generate a random k x k matrix of polynomials."""
    return [[gen_poly() for _ in range(k)] for _ in range(k)]

def transpose_matrix(matrix):
    """Transpose a matrix."""
    return [list(row) for row in zip(*matrix)]

def matrix_vector_mul(matrix, vector):
    """Multiply a matrix by a vector of polynomials."""
    result = []
    for row in matrix:
        acc = [0] * N
        for i in range(len(row)):
            acc = poly_add(acc, poly_mul(row[i], vector[i]))
        result.append(acc)
    return result

def compress(poly, q=Q):
    """Compress polynomial coefficients to 1 bit (mimicking Kyber's compression)."""
    # Map coefficients to {0, 1} based on proximity to Q/2
    return [1 if (coeff % q) > q // 4 and (coeff % q) < 3 * q // 4 else 0 for coeff in poly]

def encode(poly_vec):
    """Encode a polynomial vector to a shared secret using SHA3-256."""
    flat = sum(poly_vec, [])
    # Compress coefficients to reduce sensitivity to errors
    compressed = compress(flat)
    # Convert to bytes
    byte_array = bytearray(compressed)
    h = hashlib.sha3_256(byte_array).digest()
    return h

def generate_keypair():
    """Generate a keypair for public key encryption."""
    A = gen_matrix(K)
    s = [gen_poly() for _ in range(K)]  # Secret vector
    e = [gen_poly() for _ in range(K)]  # Error vector

    b = matrix_vector_mul(A, s)
    b = [poly_add(b[i], e[i]) for i in range(K)]  # b = A * s + e

    public_key = (A, b)
    private_key = s
    return public_key, private_key

def encapsulate(public_key):
    """Encapsulate a shared secret using the public key."""
    A, b = public_key
    r = [gen_poly() for _ in range(K)]
    e1 = [gen_poly() for _ in range(K)]
    e2 = gen_poly()

    u = matrix_vector_mul(transpose_matrix(A), r)
    u = [poly_add(u[i], e1[i]) for i in range(K)]

    # Sum polynomials for v
    v = [0] * N
    for i in range(K):
        v = poly_add(v, poly_mul(b[i], r[i]))
    v = poly_add(v, e2)

    shared_secret = encode([v])

    return (u, v), shared_secret

def decapsulate(ciphertext, private_key):
    """Decapsulate the shared secret using the private key."""
    u, v = ciphertext
    s = private_key

    # v - u * s
    us = [0] * N
    for i in range(K):
        us = poly_add(us, poly_mul(u[i], s[i]))

    m = poly_sub(v, us)  # v - u * s

    shared_secret = encode([m])

    return shared_secret

# Demo
print("=== ML-KEM-Like Key Encapsulation Simulation ===")
public_key, private_key = generate_keypair()
ciphertext, shared_enc = encapsulate(public_key)
shared_dec = decapsulate(ciphertext, private_key)

print(f"\nEncapsulated Shared Secret: {shared_enc.hex()}")
print(f"Decapsulated Shared Secret: {shared_dec.hex()}")
print("Match:", shared_enc == shared_dec)
