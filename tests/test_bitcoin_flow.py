import unittest
from unittest.mock import patch

from encoding_utils import base58check_encode, bech32_encode
from keys import (
    decode_wif, derive_addresses, privkey_to_wif,
    taproot_output_key, taproot_tweak_seckey, wif_to_privkey,
)
from main import (
    address_to_scriptpubkey, build_signed_transaction, build_unsigned_transaction,
    select_utxos, send_from_all_addresses, sign_transaction,
)
from secp256k1 import N, privkey_to_pubkey
from signer import schnorr_sign, schnorr_verify, sign, verify
from tx_builder import Transaction, TxInput, TxOutput


class EncodingAndKeyTests(unittest.TestCase):
    def test_wif_roundtrip_and_validation(self):
        for compressed in (False, True):
            wif = privkey_to_wif(1, compressed)
            self.assertEqual(decode_wif(wif), (1, compressed))
            self.assertEqual(wif_to_privkey(wif), 1)

        valid = privkey_to_wif(1)
        damaged = valid[:-1] + ("1" if valid[-1] != "1" else "2")
        with self.assertRaisesRegex(ValueError, "checksum"):
            wif_to_privkey(damaged)
        mainnet_wif = base58check_encode(bytes(32)[:-1] + b"\x01" + b"\x01", b"\x80")
        with self.assertRaisesRegex(ValueError, "Testnet"):
            wif_to_privkey(mainnet_wif)

    def test_all_derived_addresses_decode_on_testnet(self):
        addresses = derive_addresses(1)["addresses"]
        self.assertEqual(len(addresses), 5)
        for address in addresses.values():
            self.assertTrue(address_to_scriptpubkey(address))
        self.assertTrue(addresses["P2TR (taproot key-path)"].startswith("tb1p"))

    def test_bad_checksum_and_wrong_network_are_rejected(self):
        address = derive_addresses(1)["addresses"]["P2WPKH (native segwit)"]
        damaged = address[:-1] + ("q" if address[-1] != "q" else "p")
        with self.assertRaisesRegex(ValueError, "checksum"):
            address_to_scriptpubkey(damaged)
        with self.assertRaisesRegex(ValueError, "Testnet"):
            address_to_scriptpubkey(bech32_encode("bc", 0, bytes(20)))
        mainnet_legacy = base58check_encode(bytes(20), b"\x00")
        with self.assertRaisesRegex(ValueError, "Testnet"):
            address_to_scriptpubkey(mainnet_legacy)


class SignatureVectorTests(unittest.TestCase):
    def test_ecdsa_signature_is_strict_der_and_low_s(self):
        signature = sign(1, bytes.fromhex("42" * 32))
        self.assertEqual(signature[0], 0x30)
        self.assertEqual(signature[1], len(signature) - 2)
        r_length = signature[3]
        s_offset = 4 + r_length
        self.assertEqual(signature[s_offset], 0x02)
        s_length = signature[s_offset + 1]
        s = int.from_bytes(signature[s_offset + 2:s_offset + 2 + s_length], "big")
        self.assertLessEqual(s, N // 2)

    def test_bip340_official_vector_zero(self):
        message = bytes(32)
        signature = schnorr_sign(3, message, bytes(32))
        expected = bytes.fromhex(
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
            "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
        )
        self.assertEqual(signature, expected)
        public_key_x = bytes.fromhex(
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
        )
        self.assertTrue(schnorr_verify(public_key_x, message, signature))

    def test_bip341_taproot_tweak_vector(self):
        secret = int("6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa", 16)
        self.assertEqual(
            taproot_output_key(secret).hex(),
            "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
        )
        self.assertEqual(
            taproot_tweak_seckey(secret),
            int("2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9", 16),
        )

    def test_bip341_default_sighash_vector(self):
        # Input 4 from BIP341 wallet-test-vectors.json (SIGHASH_DEFAULT).
        raw = bytes.fromhex(
            "02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000"
            "d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f5833843"
            "33689228c5d28eac13366be082dc57441760d957275419a418420000000000fffffffff0689180aa63b30cb162a73c"
            "6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d92"
            "64a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893"
            "a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5"
            "f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf000000"
            "0000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff"
            "0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87"
            "f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d"
        )
        scripts = [
            "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
            "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
            "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
            "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
            "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
            "00147dd65592d0ab2fe0d0257d571abf032cd9db93dc",
            "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
            "5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
            "512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220",
        ]
        values = [420_000_000, 462_000_000, 294_000_000, 504_000_000,
                  630_000_000, 378_000_000, 672_000_000, 546_000_000, 588_000_000]
        cursor = 0
        version = int.from_bytes(raw[cursor:cursor + 4], "little")
        cursor += 4
        input_count = raw[cursor]
        cursor += 1
        inputs = []
        for index in range(input_count):
            txid = raw[cursor:cursor + 32][::-1].hex()
            cursor += 32
            vout = int.from_bytes(raw[cursor:cursor + 4], "little")
            cursor += 4
            script_length = raw[cursor]
            cursor += 1 + script_length
            sequence = raw[cursor:cursor + 4]
            cursor += 4
            txin = TxInput(txid, vout, values[index], bytes.fromhex(scripts[index]), True)
            txin.sequence = sequence
            inputs.append(txin)
        output_count = raw[cursor]
        cursor += 1
        outputs = []
        for _ in range(output_count):
            amount = int.from_bytes(raw[cursor:cursor + 8], "little")
            cursor += 8
            script_length = raw[cursor]
            cursor += 1
            script = raw[cursor:cursor + script_length]
            cursor += script_length
            outputs.append(TxOutput(amount, script))
        locktime = int.from_bytes(raw[cursor:cursor + 4], "little")
        tx = Transaction(inputs, outputs, locktime)
        tx.version = version
        self.assertEqual(
            tx.taproot_sighash(4).hex(),
            "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef",
        )

    def test_bip143_native_p2wpkh_sighash_vector(self):
        raw_outpoint_0 = bytes.fromhex("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f")
        raw_outpoint_1 = bytes.fromhex("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a")
        first = TxInput(raw_outpoint_0[::-1].hex(), 0, 625_000_000,
                        bytes.fromhex("2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac"), False)
        second = TxInput(raw_outpoint_1[::-1].hex(), 1, 600_000_000,
                         bytes.fromhex("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"), True)
        first.sequence = bytes.fromhex("eeffffff")
        outputs = [
            TxOutput(112_340_000, bytes.fromhex("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac")),
            TxOutput(223_450_000, bytes.fromhex("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac")),
        ]
        tx = Transaction([first, second], outputs, locktime=17)
        script_code = bytes.fromhex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac")
        self.assertEqual(
            tx.segwit_sighash(1, script_code).hex(),
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670",
        )


class TransactionFlowTests(unittest.TestCase):
    def setUp(self):
        self.secret = 1
        self.destination = derive_addresses(2)["addresses"]["P2WPKH (native segwit)"]

    def test_coin_selection_uses_fewest_inputs_and_deduplicates(self):
        utxos = [
            {"txid": "01" * 32, "vout": 0, "value": 4_000},
            {"txid": "02" * 32, "vout": 0, "value": 8_000},
            {"txid": "03" * 32, "vout": 0, "value": 3_000},
            {"txid": "02" * 32, "vout": 0, "value": 8_000},
        ]
        selected, total = select_utxos(utxos, 9_000, 500)
        self.assertEqual([u["value"] for u in selected], [8_000, 4_000])
        self.assertEqual(total, 12_000)

    def test_invalid_amount_and_fee_are_rejected(self):
        for amount, fee in ((0, 300), (-1, 300), (1_000, 0), (1_000, -1)):
            with self.assertRaises(ValueError):
                select_utxos([], amount, fee)

    def test_builds_and_verifies_all_supported_input_types(self):
        kinds = list(derive_addresses(self.secret)["addresses"])
        utxos = [
            {"txid": f"{index + 1:02x}" * 32, "vout": index, "value": 10_000,
             "address_type": kind}
            for index, kind in enumerate(kinds)
        ]
        tx, details = build_signed_transaction(self.secret, self.destination, 40_000, 500, utxos)
        self.assertEqual(details["change_sat"], 9_500)
        self.assertEqual(details["effective_fee_sat"], 500)
        self.assertEqual(len(tx.inputs), 5)
        self.assertEqual(len(tx.outputs), 2)
        self.assertGreater(details["vsize"], 0)

        pub_point = privkey_to_pubkey(self.secret)
        for index in (0, 1):
            script_sig = tx.inputs[index].script_sig
            sig_length = script_sig[0]
            der = script_sig[1:1 + sig_length - 1]
            self.assertTrue(verify(pub_point, tx.legacy_sighash(index, tx.inputs[index].script_pubkey), der))
        self.assertEqual(len(tx.inputs[2].witness), 2)
        self.assertEqual(len(tx.inputs[3].witness), 2)
        self.assertEqual(len(tx.inputs[4].witness), 1)
        self.assertEqual(len(tx.inputs[4].witness[0]), 64)
        self.assertTrue(schnorr_verify(
            taproot_output_key(self.secret), tx.taproot_sighash(4), tx.inputs[4].witness[0]
        ))
        self.assertEqual(tx.serialize()[4:6], b"\x00\x01")

    def test_unsigned_transaction_exists_before_signing(self):
        kinds = list(derive_addresses(self.secret)["addresses"])
        utxos = [
            {"txid": f"{index + 10:02x}" * 32, "vout": index, "value": 10_000,
             "address_type": kind}
            for index, kind in enumerate(kinds)
        ]
        tx, details = build_unsigned_transaction(
            self.secret, self.destination, 40_000, 500, utxos
        )

        self.assertEqual(details["change_sat"], 9_500)
        self.assertTrue(all(txin.script_sig == b"" for txin in tx.inputs))
        self.assertTrue(all(txin.witness == [] for txin in tx.inputs))
        unsigned_hex = tx.serialize_without_witness().hex()

        sign_transaction(self.secret, tx, utxos)
        self.assertNotEqual(tx.serialize_without_witness().hex(), unsigned_hex)
        self.assertTrue(any(txin.script_sig for txin in tx.inputs))
        self.assertTrue(any(txin.witness for txin in tx.inputs))

    def test_dust_change_becomes_explicit_effective_fee(self):
        utxo = {"txid": "11" * 32, "vout": 0, "value": 10_700,
                "address_type": "P2WPKH (native segwit)"}
        tx, details = build_signed_transaction(self.secret, self.destination, 10_000, 500, [utxo])
        self.assertEqual(len(tx.outputs), 1)
        self.assertEqual(details["change_sat"], 0)
        self.assertEqual(details["effective_fee_sat"], 700)

    def test_full_flow_scans_every_address_and_broadcasts_raw_hex(self):
        own = derive_addresses(self.secret)["addresses"]
        funded_address = own["P2TR (taproot key-path)"]
        queried, broadcast, logs, flow = [], [], [], {}

        def fake_utxos(address):
            queried.append(address)
            if address == funded_address:
                return [{"txid": "22" * 32, "vout": 0, "value": 20_000}]
            return []

        with patch("network.get_utxos", side_effect=fake_utxos), \
             patch("network.broadcast_tx", side_effect=lambda raw: broadcast.append(raw) or "mock-txid"):
            txid, raw_hex = send_from_all_addresses(
                privkey_to_wif(self.secret), self.destination, 10_000, 500,
                log=logs.append, details_out=flow,
            )
        self.assertEqual(set(queried), set(own.values()))
        self.assertEqual(txid, "mock-txid")
        self.assertEqual(broadcast, [raw_hex])
        self.assertTrue(bytes.fromhex(raw_hex))
        step4 = next(i for i, line in enumerate(logs) if line.startswith("Step 4"))
        step5 = next(i for i, line in enumerate(logs) if line.startswith("Step 5"))
        step6 = next(i for i, line in enumerate(logs) if line.startswith("Step 6"))
        step7 = next(i for i, line in enumerate(logs) if line.startswith("Step 7"))
        self.assertLess(step4, step5)
        self.assertLess(step5, step6)
        self.assertLess(step6, step7)
        self.assertIn("scriptSig/witness fields are empty", logs[step4])
        self.assertTrue(any(line.strip().startswith("unsigned_tx_hex") for line in logs))
        self.assertEqual(flow["txid"], "mock-txid")
        self.assertEqual(flow["total_in_sat"], 20_000)
        self.assertEqual(flow["amount_sat"], 10_000)
        self.assertEqual(flow["change_sat"], 9_500)
        self.assertEqual(len(flow["selected_utxos"]), 1)
        self.assertEqual([item["role"] for item in flow["outputs"]], ["recipient", "change"])


if __name__ == "__main__":
    unittest.main()
