r"""
Flask backend for the demo wallet. Thin wrapper around the core logic in
keys.py / tx_builder.py / signer.py / network.py / main.py - this file has
no crypto in it, only HTTP plumbing.

Run:
    Windows: .\.venv\Scripts\python.exe app.py
    Linux:  .venv/bin/python app.py
Then open http://127.0.0.1:5000
"""
from flask import Flask, request, jsonify, render_template

from keys import decode_wif, generate_private_key, derive_addresses
from main import address_to_scriptpubkey, send_from_all_addresses
import network

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/wallet/new", methods=["POST"])
def new_wallet():
    priv = generate_private_key()
    info = derive_addresses(priv)
    return jsonify(info)


@app.route("/api/wallet/import", methods=["POST"])
def import_wallet():
    data = request.get_json(force=True)
    wif = data.get("wif", "").strip()
    try:
        priv, compressed = decode_wif(wif)
        info = derive_addresses(priv)
        info["private_key_wif"] = wif
        info["wif_compressed"] = compressed
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": f"Invalid WIF: {e}"}), 400


@app.route("/api/balance", methods=["POST"])
def balance():
    data = request.get_json(force=True)
    address = data.get("address", "").strip()
    try:
        address_to_scriptpubkey(address)
        utxos = network.get_utxos(address)
        total_sat = sum(u["value"] for u in utxos)
        return jsonify({"address": address, "utxo_count": len(utxos),
                         "total_sat": total_sat, "utxos": utxos})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/balance/all", methods=["POST"])
def balance_all():
    """Return balances for every supported address derived from one WIF."""
    data = request.get_json(force=True)
    wif = data.get("wif", "").strip()
    try:
        private_key, _compressed = decode_wif(wif)
        balances = []
        total_sat = 0
        total_utxos = 0
        for kind, address in derive_addresses(private_key)["addresses"].items():
            utxos = network.get_utxos(address)
            address_total = sum(utxo["value"] for utxo in utxos)
            balances.append({
                "address_type": kind,
                "address": address,
                "total_sat": address_total,
                "utxo_count": len(utxos),
            })
            total_sat += address_total
            total_utxos += len(utxos)
        return jsonify({"total_sat": total_sat, "utxo_count": total_utxos,
                        "balances": balances})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/history", methods=["POST"])
def history():
    data = request.get_json(force=True)
    address = data.get("address", "").strip()
    try:
        address_to_scriptpubkey(address)
        txs = network.get_tx_history(address)
        return jsonify({"address": address, "txs": txs})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/send", methods=["POST"])
def send():
    data = request.get_json(force=True)
    wif = data.get("wif", "").strip()
    to_address = data.get("to_address", "").strip()
    logs = []
    try:
        amount_sat = data.get("amount_sat", 0)
        fee_sat = data.get("fee_sat", 300)
        txid, raw_hex = send_from_all_addresses(wif, to_address, amount_sat, fee_sat, log=logs.append)
        return jsonify({"ok": True, "txid": txid, "raw_hex": raw_hex, "logs": logs,
                         "explorer_url": f"https://mempool.space/testnet/tx/{txid}"})
    except Exception as e:
        logs.append(f"Error: {e}")
        return jsonify({"ok": False, "error": str(e), "logs": logs}), 400


if __name__ == "__main__":
    app.run(port=5000)
