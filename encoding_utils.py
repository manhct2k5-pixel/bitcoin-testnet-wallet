"""
Hashing helpers + Base58Check + Bech32/Bech32m encoding used by Bitcoin
address formats. Implemented from scratch (BIP13, BIP141, BIP173, BIP350).
"""
import hashlib
import hmac


# ---------------------------------------------------------------------------
# Hashing primitives Bitcoin uses everywhere
# ---------------------------------------------------------------------------
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def double_sha256(b: bytes) -> bytes:
    return sha256(sha256(b))


def ripemd160(b: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(b)
    return h.digest()


def hash160(b: bytes) -> bytes:
    """SHA256 then RIPEMD160 - used to build pubkey hashes / script hashes."""
    return ripemd160(sha256(b))


# ---------------------------------------------------------------------------
# Base58Check (BIP13) - used for Legacy (P2PKH) and P2SH addresses, and WIF
# ---------------------------------------------------------------------------
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    result = ""
    while n > 0:
        n, rem = divmod(n, 58)
        result = _B58_ALPHABET[rem] + result
    # preserve leading zero bytes as '1'
    n_leading_zeros = len(b) - len(b.lstrip(b"\x00"))
    return "1" * n_leading_zeros + result


def base58check_encode(payload: bytes, version: bytes) -> str:
    data = version + payload
    checksum = double_sha256(data)[:4]
    return base58_encode(data + checksum)


def base58_decode(s: str) -> bytes:
    if not isinstance(s, str) or not s:
        raise ValueError("Base58 value must be a non-empty string")
    n = 0
    for ch in s:
        try:
            digit = _B58_ALPHABET.index(ch)
        except ValueError as exc:
            raise ValueError(f"Invalid Base58 character: {ch!r}") from exc
        n = n * 58 + digit
    result = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    n_leading_zeros = len(s) - len(s.lstrip("1"))
    return b"\x00" * n_leading_zeros + result


def base58check_decode(s: str) -> tuple[bytes, bytes]:
    data = base58_decode(s)
    if len(data) < 5:
        raise ValueError("Base58Check value is too short")
    version = data[:1]
    payload = data[1:-4]
    checksum = data[-4:]
    expected = double_sha256(version + payload)[:4]
    if not hmac.compare_digest(expected, checksum):
        raise ValueError("Invalid Base58Check checksum")
    return version, payload


# ---------------------------------------------------------------------------
# Bech32 / Bech32m (BIP173 / BIP350) - used for SegWit v0 and Taproot (v1)
# ---------------------------------------------------------------------------
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values):
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_create_checksum(hrp, data, const):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or value >> frombits:
            raise ValueError("Invalid value while converting bit groups")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif not pad and (bits >= frombits or ((acc << (tobits - bits)) & maxv)):
        raise ValueError("Invalid Bech32 padding")
    return ret


def bech32_decode(address: str):
    """Decode a bech32/bech32m address -> (hrp, witver, witness_program_bytes).
    Used to turn a destination address like 'tb1q...' back into its pkh."""
    if not isinstance(address, str) or not 8 <= len(address) <= 90:
        raise ValueError("Invalid Bech32 address length")
    if any(ord(c) < 33 or ord(c) > 126 for c in address):
        raise ValueError("Invalid character in Bech32 address")
    if address.lower() != address and address.upper() != address:
        raise ValueError("Mixed-case Bech32 address")

    address = address.lower()
    pos = address.rfind("1")
    if pos < 1 or pos + 7 > len(address):
        raise ValueError("Invalid Bech32 separator position")
    hrp, data_part = address[:pos], address[pos + 1:]
    try:
        values = [_CHARSET.index(c) for c in data_part]
    except ValueError as exc:
        raise ValueError("Invalid Bech32 data character") from exc

    checksum_constant = _bech32_polymod(_bech32_hrp_expand(hrp) + values)
    if checksum_constant not in (_BECH32_CONST, _BECH32M_CONST):
        raise ValueError("Invalid Bech32 checksum")

    data = values[:-6]
    if not data:
        raise ValueError("Missing witness version")
    witver = data[0]
    if witver > 16:
        raise ValueError("Invalid witness version")
    witprog = bytes(convertbits(data[1:], 5, 8, pad=False))
    if not 2 <= len(witprog) <= 40:
        raise ValueError("Invalid witness program length")
    if witver == 0 and len(witprog) not in (20, 32):
        raise ValueError("Witness v0 program must contain 20 or 32 bytes")
    expected_constant = _BECH32_CONST if witver == 0 else _BECH32M_CONST
    if checksum_constant != expected_constant:
        raise ValueError("Wrong checksum encoding for witness version")
    return hrp, witver, witprog


def bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    """Encode a SegWit address. witver 0 -> bech32 (P2WPKH/P2WSH),
    witver 1 -> bech32m (Taproot)."""
    if not hrp or hrp.lower() != hrp or not all(33 <= ord(c) <= 126 for c in hrp):
        raise ValueError("Invalid Bech32 HRP")
    if not 0 <= witver <= 16:
        raise ValueError("Invalid witness version")
    if not 2 <= len(witprog) <= 40 or (witver == 0 and len(witprog) not in (20, 32)):
        raise ValueError("Invalid witness program length")
    const = _BECH32_CONST if witver == 0 else _BECH32M_CONST
    data = [witver] + convertbits(list(witprog), 8, 5)
    checksum = _bech32_create_checksum(hrp, data, const)
    combined = data + checksum
    address = hrp + "1" + "".join(_CHARSET[d] for d in combined)
    if len(address) > 90:
        raise ValueError("Bech32 address is too long")
    return address


def tagged_hash(tag: str, message: bytes) -> bytes:
    """BIP340 tagged SHA256, used by Schnorr and Taproot."""
    tag_hash = sha256(tag.encode("ascii"))
    return sha256(tag_hash + tag_hash + message)
