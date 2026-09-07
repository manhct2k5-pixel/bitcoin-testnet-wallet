"""
secp256k1 elliptic curve arithmetic - implemented from scratch.
This is the exact curve Bitcoin uses for ECDSA key generation and signing.

Curve equation: y^2 = x^3 + 7 (mod P)
"""

# secp256k1 domain parameters (from SEC 2: Recommended Elliptic Curve Domain Parameters)
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # field prime
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # order of G
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)


def inverse_mod(k, p):
    """Modular inverse using Fermat's little theorem (p is prime)."""
    return pow(k, p - 2, p)


def is_on_curve(point):
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_add(p1, p2):
    """Add two points on the elliptic curve (point addition / doubling)."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 != y2:
        return None  # point at infinity (p1 + (-p1))

    if x1 == x2:
        # point doubling: slope = (3x^2 + a) / (2y)
        m = (3 * x1 * x1 + A) * inverse_mod(2 * y1, P) % P
    else:
        # point addition: slope = (y2 - y1) / (x2 - x1)
        m = (y2 - y1) * inverse_mod(x2 - x1, P) % P

    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k, point):
    """Multiply a point by scalar k using double-and-add algorithm."""
    if k % N == 0 or point is None:
        return None
    if k < 0:
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def point_neg(point):
    if point is None:
        return None
    x, y = point
    return (x, (-y) % P)


def privkey_to_pubkey(privkey_int):
    """Derive the public key point from a private key integer."""
    if not isinstance(privkey_int, int) or not 1 <= privkey_int < N:
        raise ValueError("Private key must be an integer in [1, n-1]")
    pub = scalar_mult(privkey_int, G)
    assert is_on_curve(pub), "Derived public key is not on curve!"
    return pub


def pubkey_point_to_bytes(point, compressed=True):
    """Serialize a public key point to bytes (SEC format)."""
    x, y = point
    x_bytes = x.to_bytes(32, "big")
    if compressed:
        prefix = b"\x02" if y % 2 == 0 else b"\x03"
        return prefix + x_bytes
    else:
        y_bytes = y.to_bytes(32, "big")
        return b"\x04" + x_bytes + y_bytes


def lift_x(x: int):
    """Lift an x-only BIP340 public key to the curve point with even Y."""
    if not 0 <= x < P:
        return None
    y_sq = (pow(x, 3, P) + B) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else P - y)
