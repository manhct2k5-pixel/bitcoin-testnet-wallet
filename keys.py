"""Derive the supported standard single-key address types on Testnet/Signet."""
import os
from secp256k1 import N, G, scalar_mult, privkey_to_pubkey, pubkey_point_to_bytes
from encoding_utils import (
    hash160,
    base58check_encode,
    base58check_decode,
    bech32_encode,
    tagged_hash,
)

# --- network version bytes ---
# testnet                          mainnet
WIF_PREFIX = b"\xef"              # b"\x80"
P2PKH_PREFIX = b"\x6f"            # b"\x00"   -> address starts with 'm'/'n'
P2SH_PREFIX = b"\xc4"             # b"\x05"   -> address starts with '2'
BECH32_HRP = "tb"                 # "bc"      -> address starts with 'tb1'/'bc1'


def generate_private_key() -> int:
    """Cryptographically secure random private key in [1, N-1]."""
    while True:
        k = int.from_bytes(os.urandom(32), "big")
        if 0 < k < N:
            return k


def privkey_to_wif(privkey_int: int, compressed=True) -> str:
    """Wallet Import Format - human-readable private key encoding."""
    if not isinstance(privkey_int, int) or not 1 <= privkey_int < N:
        raise ValueError("Private key must be in [1, n-1]")
    payload = privkey_int.to_bytes(32, "big")
    if compressed:
        payload += b"\x01"
    return base58check_encode(payload, WIF_PREFIX)


def decode_wif(wif: str) -> tuple[int, bool]:
    """Validate and decode a Testnet/Signet WIF into (secret, compressed)."""
    version, payload = base58check_decode(wif)
    if version != WIF_PREFIX:
        raise ValueError("WIF is not for Bitcoin Testnet/Signet")
    if len(payload) == 32:
        compressed = False
        key_bytes = payload
    elif len(payload) == 33 and payload[-1] == 1:
        compressed = True
        key_bytes = payload[:-1]
    else:
        raise ValueError("Invalid WIF payload or compression flag")
    private_key = int.from_bytes(key_bytes, "big")
    if not 1 <= private_key < N:
        raise ValueError("Private key is outside the secp256k1 range")
    return private_key, compressed


def wif_to_privkey(wif: str) -> int:
    return decode_wif(wif)[0]


def taproot_tweak_seckey(privkey_int: int) -> int:
    """BIP341 key-path secret tweak for a Taproot output without script tree."""
    point = privkey_to_pubkey(privkey_int)
    secret = privkey_int if point[1] % 2 == 0 else N - privkey_int
    tweak = int.from_bytes(
        tagged_hash("TapTweak", point[0].to_bytes(32, "big")), "big"
    )
    if tweak >= N:
        raise ValueError("Invalid Taproot tweak")
    tweaked = (secret + tweak) % N
    if tweaked == 0:
        raise ValueError("Invalid tweaked Taproot private key")
    return tweaked


def taproot_output_key(privkey_int: int) -> bytes:
    """Return the x-only output key for a BIP86-style key-path address."""
    tweaked_point = scalar_mult(taproot_tweak_seckey(privkey_int), G)
    return tweaked_point[0].to_bytes(32, "big")


def derive_addresses(privkey_int: int) -> dict:
    """Return supported standard single-key Testnet/Signet addresses."""
    pub_point = privkey_to_pubkey(privkey_int)
    pubkey_c = pubkey_point_to_bytes(pub_point, compressed=True)   # 33 bytes
    pubkey_u = pubkey_point_to_bytes(pub_point, compressed=False)  # 65 bytes

    pkh = hash160(pubkey_c)
    pkh_uncompressed = hash160(pubkey_u)

    # 1) Legacy P2PKH: version_byte + HASH160(pubkey), Base58Check
    p2pkh_address = base58check_encode(pkh, P2PKH_PREFIX)
    p2pkh_uncompressed_address = base58check_encode(pkh_uncompressed, P2PKH_PREFIX)

    # 2) Native SegWit P2WPKH: witness v0 program = HASH160(pubkey), Bech32
    p2wpkh_address = bech32_encode(BECH32_HRP, 0, pkh)

    # 3) P2SH-wrapped SegWit (P2SH-P2WPKH): redeemScript = OP_0 <pkh>,
    #    address = Base58Check(HASH160(redeemScript))
    redeem_script = b"\x00\x14" + pkh  # OP_0 PUSH(20) <pkh>
    script_hash = hash160(redeem_script)
    p2sh_p2wpkh_address = base58check_encode(script_hash, P2SH_PREFIX)

    # 4) Taproot key-path (BIP341/BIP86 style, no script tree).
    taproot_address = bech32_encode(BECH32_HRP, 1, taproot_output_key(privkey_int))

    return {
        "private_key_int": privkey_int,
        "private_key_wif": privkey_to_wif(privkey_int),
        "public_key_compressed": pubkey_c.hex(),
        "pubkey_hash160": pkh.hex(),
        "addresses": {
            "P2PKH (legacy)": p2pkh_address,
            "P2PKH (legacy, uncompressed)": p2pkh_uncompressed_address,
            "P2WPKH (native segwit)": p2wpkh_address,
            "P2SH-P2WPKH (segwit wrapped)": p2sh_p2wpkh_address,
            "P2TR (taproot key-path)": taproot_address,
        },
    }


if __name__ == "__main__":
    priv = generate_private_key()
    info = derive_addresses(priv)
    print("Private key (int):", info["private_key_int"])
    print("Private key (WIF): ", info["private_key_wif"])
    print("Public key (compressed):", info["public_key_compressed"])
    print("\nSupported single-key address types derived from this private key:")
    for kind, addr in info["addresses"].items():
        print(f"  {kind:35s} -> {addr}")
