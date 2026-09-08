"""Build, sign and broadcast standard single-key Bitcoin transactions.

Flow: WIF -> addresses -> UTXOs -> coin selection -> unsigned transaction
-> per-input sighash -> signature -> signed transaction -> raw hex -> broadcast.
The application is deliberately locked to Bitcoin Testnet/Signet address bytes.
"""
from encoding_utils import base58check_decode, bech32_decode, hash160
from keys import derive_addresses, taproot_output_key, taproot_tweak_seckey, wif_to_privkey
from secp256k1 import privkey_to_pubkey, pubkey_point_to_bytes
from signer import schnorr_sign, sign
from tx_builder import (
    Transaction, TxInput, TxOutput, build_p2pkh_script_sig,
    p2pkh_script_pubkey, p2sh_script_pubkey, p2tr_script_pubkey,
    p2wpkh_script_pubkey, push_data,
)
import network


TESTNET_HRP = "tb"
TESTNET_P2PKH_PREFIX = b"\x6f"
TESTNET_P2SH_PREFIX = b"\xc4"
MAX_MONEY = 21_000_000 * 100_000_000
P2WPKH_CHANGE_DUST = 294


def validate_payment(amount_sat: int, fee_sat: int) -> None:
    if not isinstance(amount_sat, int) or isinstance(amount_sat, bool) or not 0 < amount_sat <= MAX_MONEY:
        raise ValueError("Amount must be a positive integer number of satoshis")
    if not isinstance(fee_sat, int) or isinstance(fee_sat, bool) or not 0 < fee_sat <= MAX_MONEY:
        raise ValueError("Fee must be a positive integer number of satoshis")
    if amount_sat + fee_sat > MAX_MONEY:
        raise ValueError("Amount plus fee exceeds Bitcoin's maximum supply")


def select_utxos(utxos: list, target_sat: int, fee_sat: int = 300):
    """Choose the minimum possible input count by taking largest UTXOs first."""
    validate_payment(target_sat, fee_sat)
    normalized, seen = [], set()
    for utxo in utxos:
        if not isinstance(utxo, dict):
            raise ValueError("Malformed UTXO response")
        try:
            value = utxo["value"]
            key = (utxo["txid"], utxo["vout"])
        except KeyError as exc:
            raise ValueError(f"UTXO is missing field {exc.args[0]}") from exc
        if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= MAX_MONEY:
            raise ValueError("UTXO contains an invalid value")
        if key not in seen:
            seen.add(key)
            normalized.append(utxo)

    chosen, total = [], 0
    required = target_sat + fee_sat
    for utxo in sorted(normalized, key=lambda item: item["value"], reverse=True):
        chosen.append(utxo)
        total += utxo["value"]
        if total >= required:
            return chosen, total
    raise ValueError(f"Not enough funds: have {total} sat, need {required} sat")


def address_to_scriptpubkey(address: str) -> bytes:
    """Validate a Testnet/Signet destination and return its scriptPubKey."""
    if not isinstance(address, str) or not address:
        raise ValueError("Destination address is required")
    if address.lower().startswith(("tb1", "bc1", "bcrt1")):
        hrp, witness_version, witness_program = bech32_decode(address)
        if hrp != TESTNET_HRP:
            raise ValueError("Destination must be a Bitcoin Testnet/Signet address")
        opcode = 0 if witness_version == 0 else 0x50 + witness_version
        return bytes([opcode, len(witness_program)]) + witness_program

    version, payload = base58check_decode(address)
    if len(payload) != 20:
        raise ValueError("Base58 address payload must contain 20 bytes")
    if version == TESTNET_P2PKH_PREFIX:
        return p2pkh_script_pubkey(payload)
    if version == TESTNET_P2SH_PREFIX:
        return p2sh_script_pubkey(payload)
    raise ValueError("Destination must be a Bitcoin Testnet/Signet address")


def dust_threshold(script_pubkey: bytes) -> int:
    """Standard relay dust threshold at Bitcoin Core's default 1 sat/vB rate."""
    if script_pubkey.startswith(b"\x76\xa9\x14") and len(script_pubkey) == 25:
        return 546
    if script_pubkey.startswith(b"\xa9\x14") and len(script_pubkey) == 23:
        return 540
    if script_pubkey.startswith(b"\x00\x14") and len(script_pubkey) == 22:
        return 294
    return 330


def _input_for_utxo(utxo: dict, pubkey_hash: bytes, uncompressed_hash: bytes,
                    taproot_key: bytes) -> TxInput:
    kind = utxo["address_type"]
    common = (utxo["txid"], utxo["vout"], utxo["value"])
    if kind == "P2PKH (legacy)":
        return TxInput(*common, p2pkh_script_pubkey(pubkey_hash), is_segwit=False)
    if kind == "P2PKH (legacy, uncompressed)":
        return TxInput(*common, p2pkh_script_pubkey(uncompressed_hash), is_segwit=False)
    if kind == "P2WPKH (native segwit)":
        return TxInput(*common, p2wpkh_script_pubkey(pubkey_hash), is_segwit=True)
    if kind == "P2SH-P2WPKH (segwit wrapped)":
        redeem_script = p2wpkh_script_pubkey(pubkey_hash)
        return TxInput(*common, p2sh_script_pubkey(hash160(redeem_script)),
                       is_segwit=True, redeem_script=redeem_script)
    if kind == "P2TR (taproot key-path)":
        return TxInput(*common, p2tr_script_pubkey(taproot_key), is_segwit=True)
    raise ValueError(f"Unsupported UTXO address type: {kind}")


def build_unsigned_transaction(privkey_int: int, to_address: str, amount_sat: int,
                               fee_sat: int, chosen_utxos: list):
    """Build inputs and outputs while leaving every scriptSig/witness empty."""
    validate_payment(amount_sat, fee_sat)
    destination_script = address_to_scriptpubkey(to_address)
    minimum_output = dust_threshold(destination_script)
    if amount_sat < minimum_output:
        raise ValueError(f"Recipient output is dust: minimum is {minimum_output} sat")
    if not chosen_utxos:
        raise ValueError("At least one UTXO must be selected")

    total_in = sum(utxo["value"] for utxo in chosen_utxos)
    if total_in < amount_sat + fee_sat:
        raise ValueError("Selected UTXOs do not cover amount plus fee")

    pub_point = privkey_to_pubkey(privkey_int)
    pubkey_compressed = pubkey_point_to_bytes(pub_point, compressed=True)
    pubkey_uncompressed = pubkey_point_to_bytes(pub_point, compressed=False)
    pubkey_hash = hash160(pubkey_compressed)
    uncompressed_hash = hash160(pubkey_uncompressed)
    taproot_key = taproot_output_key(privkey_int)
    tx_inputs = [_input_for_utxo(u, pubkey_hash, uncompressed_hash, taproot_key)
                 for u in chosen_utxos]
    tx_outputs = [TxOutput(amount_sat, destination_script)]

    change_candidate = total_in - amount_sat - fee_sat
    change_sat = change_candidate if change_candidate >= P2WPKH_CHANGE_DUST else 0
    if change_sat:
        tx_outputs.append(TxOutput(change_sat, p2wpkh_script_pubkey(pubkey_hash)))

    tx = Transaction(tx_inputs, tx_outputs)
    effective_fee = total_in - sum(output.value_sat for output in tx.outputs)
    return tx, {
        "total_in_sat": total_in,
        "change_sat": change_sat,
        "requested_fee_sat": fee_sat,
        "effective_fee_sat": effective_fee,
    }


def sign_transaction(privkey_int: int, tx: Transaction, chosen_utxos: list,
                     log=None) -> Transaction:
    """Create each input sighash and attach its address-specific signature."""
    if not isinstance(tx, Transaction):
        raise ValueError("A Transaction instance is required")
    if len(tx.inputs) != len(chosen_utxos):
        raise ValueError("UTXO count does not match transaction input count")

    pub_point = privkey_to_pubkey(privkey_int)
    pubkey_compressed = pubkey_point_to_bytes(pub_point, compressed=True)
    pubkey_uncompressed = pubkey_point_to_bytes(pub_point, compressed=False)
    pubkey_hash = hash160(pubkey_compressed)
    script_code_segwit = p2pkh_script_pubkey(pubkey_hash)
    tweaked_taproot_secret = taproot_tweak_seckey(privkey_int)
    for index, (txin, utxo) in enumerate(zip(tx.inputs, chosen_utxos)):
        kind = utxo["address_type"]
        if kind in ("P2PKH (legacy)", "P2PKH (legacy, uncompressed)"):
            message_hash = tx.legacy_sighash(index, txin.script_pubkey)
            if log:
                log(f"Step 5 - Input {index}: Legacy sighash = {message_hash.hex()}")
            public_key = pubkey_uncompressed if "uncompressed" in kind else pubkey_compressed
            txin.script_sig = build_p2pkh_script_sig(sign(privkey_int, message_hash), public_key)
            if log:
                log(f"Step 6 - Input {index}: attached ECDSA DER low-S signature to scriptSig")
        elif kind in ("P2WPKH (native segwit)", "P2SH-P2WPKH (segwit wrapped)"):
            message_hash = tx.segwit_sighash(index, script_code_segwit)
            if log:
                log(f"Step 5 - Input {index}: BIP143 sighash = {message_hash.hex()}")
            txin.witness = [sign(privkey_int, message_hash) + b"\x01", pubkey_compressed]
            if kind == "P2SH-P2WPKH (segwit wrapped)":
                txin.script_sig = push_data(txin.redeem_script)
            if log:
                location = "redeemScript + witness" if "P2SH" in kind else "witness"
                log(f"Step 6 - Input {index}: attached ECDSA DER low-S signature to {location}")
        elif kind == "P2TR (taproot key-path)":
            message_hash = tx.taproot_sighash(index)
            if log:
                log(f"Step 5 - Input {index}: BIP341 sighash = {message_hash.hex()}")
            txin.witness = [schnorr_sign(tweaked_taproot_secret, message_hash)]
            if log:
                log(f"Step 6 - Input {index}: attached BIP340 Schnorr signature to witness")
        else:
            raise ValueError(f"Unsupported UTXO address type: {kind}")
    return tx


def build_signed_transaction(privkey_int: int, to_address: str, amount_sat: int,
                             fee_sat: int, chosen_utxos: list):
    """Compatibility wrapper: build unsigned first, then sign in a separate step."""
    tx, details = build_unsigned_transaction(
        privkey_int, to_address, amount_sat, fee_sat, chosen_utxos
    )
    sign_transaction(privkey_int, tx, chosen_utxos)
    details["vsize"] = tx.vsize()
    return tx, details


def send_from_all_addresses(wif_privkey: str, to_address: str, amount_sat: int,
                            fee_sat: int = 300, log=print, details_out=None):
    """Execute the complete eight-step Testnet transaction flow."""
    validate_payment(amount_sat, fee_sat)
    privkey_int = wif_to_privkey(wif_privkey)
    address_to_scriptpubkey(to_address)  # fail before doing network work

    info = derive_addresses(privkey_int)
    log("Step 1 - Derived supported single-key address types from private key:")
    for kind, address in info["addresses"].items():
        log(f"  {kind}: {address}")

    all_utxos = []
    for kind, address in info["addresses"].items():
        for response_utxo in network.get_utxos(address):
            utxo = dict(response_utxo)
            utxo.update(address_type=kind, address=address)
            all_utxos.append(utxo)
    if not all_utxos:
        raise RuntimeError("No UTXOs found. Fund one of the derived Testnet addresses first.")
    log(f"Step 2 - Found {len(all_utxos)} UTXO(s) across all supported addresses")

    chosen, total_in = select_utxos(all_utxos, amount_sat, fee_sat)
    log(f"Step 3 - Selected {len(chosen)} UTXO(s), total_in={total_in} sat "
        f"(need {amount_sat + fee_sat} sat)")
    tx, details = build_unsigned_transaction(
        privkey_int, to_address, amount_sat, fee_sat, chosen
    )
    unsigned_hex = tx.serialize_without_witness().hex()
    log(f"Step 4 - Constructed unsigned transaction with {len(tx.inputs)} input(s) "
        f"and {len(tx.outputs)} output(s); all scriptSig/witness fields are empty")
    log(f"  unsigned_tx_hex = {unsigned_hex}")
    if details["change_sat"]:
        log(f"  Change output: {details['change_sat']} sat to native SegWit")
    elif details["effective_fee_sat"] > fee_sat:
        log(f"  Remaining {details['effective_fee_sat'] - fee_sat} sat is below the "
            f"{P2WPKH_CHANGE_DUST} sat change dust threshold and was added to the fee")

    sign_transaction(privkey_int, tx, chosen, log=log)
    details["vsize"] = tx.vsize()

    if details_out is not None:
        selected_keys = {(item["txid"], item["vout"]) for item in chosen}
        change_address = info["addresses"]["P2WPKH (native segwit)"]
        outputs = [{
            "role": "recipient",
            "address": to_address,
            "value": amount_sat,
            "vout": 0,
        }]
        if details["change_sat"]:
            outputs.append({
                "role": "change",
                "address": change_address,
                "value": details["change_sat"],
                "vout": 1,
            })
        details_out.update({
            **details,
            "amount_sat": amount_sat,
            "input_count": len(chosen),
            "output_count": len(outputs),
            "unsigned_tx_hex": unsigned_hex,
            "selected_utxos": [dict(item) for item in chosen],
            "unselected_utxos": [
                dict(item) for item in all_utxos
                if (item["txid"], item["vout"]) not in selected_keys
            ],
            "outputs": outputs,
        })

    raw_hex = tx.serialize().hex()
    log(f"Step 7 - Serialized signed transaction: {len(raw_hex) // 2} bytes, "
        f"{details['vsize']} vB, effective fee={details['effective_fee_sat']} sat")
    txid = network.broadcast_tx(raw_hex)
    if details_out is not None:
        details_out["txid"] = txid
    log(f"Step 8 - Broadcast to Bitcoin Testnet. txid = {txid}")
    return txid, raw_hex


if __name__ == "__main__":
    print("Use the Flask UI or call send_from_all_addresses with a funded Testnet WIF.")
