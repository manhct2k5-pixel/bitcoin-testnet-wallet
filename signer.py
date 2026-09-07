"""
Step 5: Hash and sign unsigned messages - ECDSA over secp256k1, from scratch.
Enforces "canonical form": low-S value (BIP62) + strict DER encoding (BIP66),
otherwise modern Bitcoin nodes will reject the transaction as non-standard.
"""
import hmac
import hashlib
import os
from secp256k1 import N, P, G, lift_x, point_add, point_neg, scalar_mult, inverse_mod
from encoding_utils import tagged_hash

HALF_N = N // 2


def _deterministic_k(privkey: int, msg_hash: bytes) -> int:
    """RFC6979 deterministic nonce generation (avoids the catastrophic
    'reused nonce leaks private key' bug from weak/random k)."""
    v = b"\x01" * 32
    k = b"\x00" * 32
    priv_bytes = privkey.to_bytes(32, "big")

    k = hmac.new(k, v + b"\x00" + priv_bytes + msg_hash, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + priv_bytes + msg_hash, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 0 < candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(privkey: int, msg_hash: bytes) -> bytes:
    """
    Sign a 32-byte message hash. Returns DER-encoded (r, s), low-S enforced.
    msg_hash must already be the double-SHA256 sighash Bitcoin expects.
    """
    if not isinstance(privkey, int) or not 1 <= privkey < N:
        raise ValueError("Invalid private key")
    if not isinstance(msg_hash, bytes) or len(msg_hash) != 32:
        raise ValueError("ECDSA expects a 32-byte message hash")
    z = int.from_bytes(msg_hash, "big")
    k = _deterministic_k(privkey, msg_hash)

    x, _y = scalar_mult(k, G)
    r = x % N
    s = (inverse_mod(k, N) * (z + r * privkey)) % N

    # BIP62 canonical form: enforce low-S (s <= N/2)
    if s > HALF_N:
        s = N - s

    return _der_encode(r, s)


def schnorr_sign(privkey: int, message: bytes, aux_rand: bytes = None) -> bytes:
    """Create a 64-byte BIP340 Schnorr signature."""
    if not isinstance(privkey, int) or not 1 <= privkey < N:
        raise ValueError("Invalid private key")
    if not isinstance(message, bytes):
        raise ValueError("Message must be bytes")
    if aux_rand is None:
        aux_rand = os.urandom(32)
    if len(aux_rand) != 32:
        raise ValueError("BIP340 auxiliary randomness must be 32 bytes")

    pub = scalar_mult(privkey, G)
    d = privkey if pub[1] % 2 == 0 else N - privkey
    pub_x = pub[0].to_bytes(32, "big")
    masked = bytes(a ^ b for a, b in zip(
        d.to_bytes(32, "big"), tagged_hash("BIP0340/aux", aux_rand)
    ))
    nonce = int.from_bytes(
        tagged_hash("BIP0340/nonce", masked + pub_x + message), "big"
    ) % N
    if nonce == 0:
        raise RuntimeError("BIP340 nonce generation produced zero")

    r_point = scalar_mult(nonce, G)
    k = nonce if r_point[1] % 2 == 0 else N - nonce
    r_bytes = r_point[0].to_bytes(32, "big")
    challenge = int.from_bytes(
        tagged_hash("BIP0340/challenge", r_bytes + pub_x + message), "big"
    ) % N
    signature = r_bytes + ((k + challenge * d) % N).to_bytes(32, "big")
    if not schnorr_verify(pub_x, message, signature):
        raise RuntimeError("Internal Schnorr signature verification failed")
    return signature


def schnorr_verify(public_key_x: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a BIP340 signature against a 32-byte x-only public key."""
    if not isinstance(public_key_x, bytes) or len(public_key_x) != 32:
        return False
    if not isinstance(message, bytes) or not isinstance(signature, bytes) or len(signature) != 64:
        return False
    pub = lift_x(int.from_bytes(public_key_x, "big"))
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if pub is None or r >= P or s >= N:
        return False
    challenge = int.from_bytes(
        tagged_hash("BIP0340/challenge", signature[:32] + public_key_x + message), "big"
    ) % N
    r_point = point_add(scalar_mult(s, G), scalar_mult(challenge, point_neg(pub)))
    return r_point is not None and r_point[1] % 2 == 0 and r_point[0] == r


def _der_encode_int(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:  # prepend 0x00 if high bit set (would look negative)
        b = b"\x00" + b
    return b


def _der_encode(r: int, s: int) -> bytes:
    r_b = _der_encode_int(r)
    s_b = _der_encode_int(s)
    body = b"\x02" + len(r_b).to_bytes(1, "big") + r_b
    body += b"\x02" + len(s_b).to_bytes(1, "big") + s_b
    return b"\x30" + len(body).to_bytes(1, "big") + body


def verify(pubkey_point, msg_hash: bytes, der_sig: bytes) -> bool:
    """Sanity-check verification (not required for the flow, but good to
    confirm your signer actually produces valid signatures)."""
    # minimal DER parse
    assert der_sig[0] == 0x30
    idx = 2
    assert der_sig[idx] == 0x02
    rlen = der_sig[idx + 1]
    r = int.from_bytes(der_sig[idx + 2: idx + 2 + rlen], "big")
    idx = idx + 2 + rlen
    assert der_sig[idx] == 0x02
    slen = der_sig[idx + 1]
    s = int.from_bytes(der_sig[idx + 2: idx + 2 + slen], "big")

    z = int.from_bytes(msg_hash, "big")
    w = inverse_mod(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    from secp256k1 import point_add
    x, _y = point_add(scalar_mult(u1, G), scalar_mult(u2, pubkey_point))
    return x % N == r
