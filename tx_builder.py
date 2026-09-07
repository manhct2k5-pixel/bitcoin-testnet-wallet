"""
Steps 4, 6, 7: construct unsigned tx, compute correct sighash per input type,
build the signed tx (scriptSig for legacy, witness for segwit), and combine
everything into the final raw transaction bytes.

Raw tx format (Bitcoin wire format):
  version(4LE) | in_count(varint) | inputs | out_count(varint) | outputs
  | [witness data if any input is segwit] | locktime(4LE)

Each input: prev_txid(32, byte-reversed) | prev_vout(4LE) | scriptSig(varlen) | sequence(4LE)
Each output: value(8LE, satoshis) | scriptPubKey(varlen)
"""
from encoding_utils import double_sha256, sha256, tagged_hash

SIGHASH_ALL = 1


def varint(n: int) -> bytes:
    if not isinstance(n, int) or n < 0:
        raise ValueError("CompactSize value must be a non-negative integer")
    if n < 0xfd:
        return n.to_bytes(1, "little")
    elif n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    elif n <= 0xffffffff:
        return b"\xfe" + n.to_bytes(4, "little")
    else:
        return b"\xff" + n.to_bytes(8, "little")


def push_data(data: bytes) -> bytes:
    """Script push opcode for arbitrary data (used inside scriptSig)."""
    n = len(data)
    if n < 0x4c:
        return n.to_bytes(1, "little") + data
    elif n <= 0xff:
        return b"\x4c" + n.to_bytes(1, "little") + data
    else:
        return b"\x4d" + n.to_bytes(2, "little") + data


class TxInput:
    def __init__(self, txid_hex: str, vout: int, value_sat: int, script_pubkey: bytes,
                 is_segwit: bool, redeem_script: bytes = None):
        try:
            txid = bytes.fromhex(txid_hex)
        except (TypeError, ValueError) as exc:
            raise ValueError("UTXO txid must be 64 hexadecimal characters") from exc
        if len(txid) != 32:
            raise ValueError("UTXO txid must contain 32 bytes")
        if not isinstance(vout, int) or not 0 <= vout <= 0xffffffff:
            raise ValueError("UTXO vout is outside the uint32 range")
        if not isinstance(value_sat, int) or not 0 <= value_sat <= 21_000_000 * 100_000_000:
            raise ValueError("Invalid UTXO value")
        self.txid = txid[::-1]  # internal byte order is reversed
        self.vout = vout
        self.value_sat = value_sat          # needed for BIP143 sighash
        self.script_pubkey = script_pubkey  # the UTXO's locking script
        self.is_segwit = is_segwit
        self.redeem_script = redeem_script  # only for P2SH-P2WPKH
        self.script_sig = b""               # filled in after signing
        self.witness = []                   # filled in after signing (list of byte-strings)
        self.sequence = b"\xff\xff\xff\xff"

    def serialize(self, for_signing_script: bytes = None) -> bytes:
        if for_signing_script is not None:
            script = varint(len(for_signing_script)) + for_signing_script
        else:
            script = varint(len(self.script_sig)) + self.script_sig
        return self.txid + self.vout.to_bytes(4, "little") + script + self.sequence


class TxOutput:
    def __init__(self, value_sat: int, script_pubkey: bytes):
        if not isinstance(value_sat, int) or not 0 <= value_sat <= 21_000_000 * 100_000_000:
            raise ValueError("Invalid transaction output value")
        if not isinstance(script_pubkey, bytes) or not script_pubkey:
            raise ValueError("Output scriptPubKey must be non-empty bytes")
        self.value_sat = value_sat
        self.script_pubkey = script_pubkey

    def serialize(self) -> bytes:
        return (self.value_sat.to_bytes(8, "little") +
                varint(len(self.script_pubkey)) + self.script_pubkey)


class Transaction:
    def __init__(self, inputs, outputs, locktime=0):
        if not inputs or not outputs:
            raise ValueError("Transaction needs at least one input and one output")
        if not isinstance(locktime, int) or not 0 <= locktime <= 0xffffffff:
            raise ValueError("Invalid locktime")
        self.version = 1
        self.inputs = inputs
        self.outputs = outputs
        self.locktime = locktime

    def has_segwit_input(self):
        return any(i.is_segwit for i in self.inputs)

    # -- legacy sighash (pre-segwit inputs) --------------------------------
    def legacy_sighash(self, input_index: int, script_code: bytes) -> bytes:
        """BIP: original sighash algorithm. Temporarily blank out all other
        scriptSigs and put script_code into the one being signed."""
        tmp_inputs = b""
        for i, txin in enumerate(self.inputs):
            script = script_code if i == input_index else b""
            tmp_inputs += txin.serialize(for_signing_script=script)

        tmp_outputs = b"".join(o.serialize() for o in self.outputs)

        preimage = (
            self.version.to_bytes(4, "little") +
            varint(len(self.inputs)) + tmp_inputs +
            varint(len(self.outputs)) + tmp_outputs +
            self.locktime.to_bytes(4, "little") +
            SIGHASH_ALL.to_bytes(4, "little")
        )
        return double_sha256(preimage)

    # -- BIP143 sighash (SegWit v0 inputs: P2WPKH / P2SH-P2WPKH) ----------
    def _hash_prevouts(self):
        buf = b"".join(i.txid + i.vout.to_bytes(4, "little") for i in self.inputs)
        return double_sha256(buf)

    def _hash_sequence(self):
        buf = b"".join(i.sequence for i in self.inputs)
        return double_sha256(buf)

    def _hash_outputs(self):
        buf = b"".join(o.serialize() for o in self.outputs)
        return double_sha256(buf)

    def segwit_sighash(self, input_index: int, script_code: bytes) -> bytes:
        """BIP143: fixes quadratic-hashing vulnerability, and is mandatory
        for P2WPKH / P2SH-P2WPKH / P2WSH inputs."""
        txin = self.inputs[input_index]

        hash_prevouts = self._hash_prevouts()
        hash_sequence = self._hash_sequence()
        hash_outputs = self._hash_outputs()

        preimage = (
            self.version.to_bytes(4, "little") +             # nVersion
            hash_prevouts +
            hash_sequence +
            txin.txid + txin.vout.to_bytes(4, "little") +     # outpoint
            varint(len(script_code)) + script_code +          # scriptCode
            txin.value_sat.to_bytes(8, "little") +             # amount
            txin.sequence +
            hash_outputs +
            self.locktime.to_bytes(4, "little") +
            SIGHASH_ALL.to_bytes(4, "little")
        )
        return double_sha256(preimage)

    # -- BIP341 sighash (Taproot key-path, SIGHASH_DEFAULT) ---------------
    def taproot_sighash(self, input_index: int) -> bytes:
        """Hash one Taproot key-path input using BIP341 SIGHASH_DEFAULT."""
        if not 0 <= input_index < len(self.inputs):
            raise IndexError("Input index out of range")
        outpoints = b"".join(i.txid + i.vout.to_bytes(4, "little") for i in self.inputs)
        amounts = b"".join(i.value_sat.to_bytes(8, "little") for i in self.inputs)
        scripts = b"".join(varint(len(i.script_pubkey)) + i.script_pubkey for i in self.inputs)
        sequences = b"".join(i.sequence for i in self.inputs)
        outputs = b"".join(o.serialize() for o in self.outputs)

        sigmsg = (
            b"\x00" +                                      # SIGHASH_DEFAULT
            self.version.to_bytes(4, "little") +
            self.locktime.to_bytes(4, "little") +
            sha256(outpoints) +
            sha256(amounts) +
            sha256(scripts) +
            sha256(sequences) +
            sha256(outputs) +
            b"\x00" +                                      # ext_flag=0, no annex
            input_index.to_bytes(4, "little")
        )
        return tagged_hash("TapSighash", b"\x00" + sigmsg)  # epoch 0

    # -- final serialization -------------------------------------------
    def serialize(self) -> bytes:
        segwit = self.has_segwit_input()
        out = self.version.to_bytes(4, "little")

        if segwit:
            out += b"\x00\x01"  # marker + flag (BIP144)

        out += varint(len(self.inputs))
        out += b"".join(i.serialize() for i in self.inputs)
        out += varint(len(self.outputs))
        out += b"".join(o.serialize() for o in self.outputs)

        if segwit:
            for txin in self.inputs:
                if txin.is_segwit:
                    out += varint(len(txin.witness))
                    for item in txin.witness:
                        out += varint(len(item)) + item
                else:
                    out += varint(0)  # empty witness for non-segwit inputs

        out += self.locktime.to_bytes(4, "little")
        return out

    def txid(self) -> str:
        """Real txid excludes witness data (double SHA256 of the
        non-segwit-serialized tx, byte-reversed for display)."""
        base = self.serialize_without_witness()
        return double_sha256(base)[::-1].hex()

    def serialize_without_witness(self) -> bytes:
        base = self.version.to_bytes(4, "little")
        base += varint(len(self.inputs))
        base += b"".join(i.serialize() for i in self.inputs)
        base += varint(len(self.outputs))
        base += b"".join(o.serialize() for o in self.outputs)
        base += self.locktime.to_bytes(4, "little")
        return base

    def vsize(self) -> int:
        """Return virtual size after signatures/witnesses have been attached."""
        stripped_size = len(self.serialize_without_witness())
        total_size = len(self.serialize())
        weight = stripped_size * 4 + (total_size - stripped_size)
        return (weight + 3) // 4


def p2pkh_script_pubkey(pkh: bytes) -> bytes:
    # OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    return b"\x76\xa9\x14" + pkh + b"\x88\xac"


def p2wpkh_script_pubkey(pkh: bytes) -> bytes:
    # OP_0 <20 bytes>
    return b"\x00\x14" + pkh


def p2sh_script_pubkey(script_hash: bytes) -> bytes:
    # OP_HASH160 <20 bytes> OP_EQUAL
    return b"\xa9\x14" + script_hash + b"\x87"


def p2tr_script_pubkey(output_key_x: bytes) -> bytes:
    if len(output_key_x) != 32:
        raise ValueError("Taproot output key must contain 32 bytes")
    return b"\x51\x20" + output_key_x


def build_p2pkh_script_sig(signature_der: bytes, pubkey: bytes) -> bytes:
    sig_with_hashtype = signature_der + SIGHASH_ALL.to_bytes(1, "little")
    return push_data(sig_with_hashtype) + push_data(pubkey)
