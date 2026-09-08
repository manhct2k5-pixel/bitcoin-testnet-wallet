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
        utxos = []
        for response_utxo in network.get_utxos(address):
            item = dict(response_utxo)
            item["explorer_url"] = f"https://mempool.space/testnet/tx/{item['txid']}"
            utxos.append(item)
        confirmed = [item for item in utxos if item.get("status", {}).get("confirmed")]
        pending = [item for item in utxos if not item.get("status", {}).get("confirmed")]
        total_sat = sum(item["value"] for item in utxos)
        return jsonify({
            "address": address,
            "total_sat": total_sat,
            "confirmed_sat": sum(item["value"] for item in confirmed),
            "pending_sat": sum(item["value"] for item in pending),
            "utxo_count": len(utxos),
            "confirmed_utxo_count": len(confirmed),
            "pending_utxo_count": len(pending),
            "utxos": utxos,
        })
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
        all_utxos = []
        total_sat = 0
        total_utxos = 0
        confirmed_sat = 0
        pending_sat = 0
        confirmed_utxos = 0
        pending_utxos = 0
        for kind, address in derive_addresses(private_key)["addresses"].items():
            utxos = network.get_utxos(address)
            for utxo in utxos:
                item = dict(utxo)
                item.update(
                    address_type=kind,
                    address=address,
                    explorer_url=f"https://mempool.space/testnet/tx/{item['txid']}",
                )
                all_utxos.append(item)
            address_total = sum(utxo["value"] for utxo in utxos)
            address_confirmed = sum(
                utxo["value"] for utxo in utxos
                if utxo.get("status", {}).get("confirmed")
            )
            address_pending = address_total - address_confirmed
            address_confirmed_count = sum(
                1 for utxo in utxos if utxo.get("status", {}).get("confirmed")
            )
            address_pending_count = len(utxos) - address_confirmed_count
            balances.append({
                "address_type": kind,
                "address": address,
                "total_sat": address_total,
                "utxo_count": len(utxos),
                "confirmed_sat": address_confirmed,
                "pending_sat": address_pending,
                "confirmed_utxo_count": address_confirmed_count,
                "pending_utxo_count": address_pending_count,
            })
            total_sat += address_total
            total_utxos += len(utxos)
            confirmed_sat += address_confirmed
            pending_sat += address_pending
            confirmed_utxos += address_confirmed_count
            pending_utxos += address_pending_count
        return jsonify({
            "total_sat": total_sat,
            "confirmed_sat": confirmed_sat,
            "pending_sat": pending_sat,
            "utxo_count": total_utxos,
            "confirmed_utxo_count": confirmed_utxos,
            "pending_utxo_count": pending_utxos,
            "balances": balances,
            "utxos": all_utxos,
        })
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
    transaction = {}
    try:
        amount_sat = data.get("amount_sat", 0)
        fee_sat = data.get("fee_sat", 300)
        txid, raw_hex = send_from_all_addresses(
            wif, to_address, amount_sat, fee_sat,
            log=logs.append, details_out=transaction,
        )
        return jsonify({"ok": True, "txid": txid, "raw_hex": raw_hex, "logs": logs,
                         "transaction": transaction,
                         "explorer_url": f"https://mempool.space/testnet/tx/{txid}"})
    except Exception as e:
        logs.append(f"Error: {e}")
        return jsonify({"ok": False, "error": str(e), "logs": logs,
                        "transaction": transaction}), 400


if __name__ == "__main__":
    app.run(port=5000)
