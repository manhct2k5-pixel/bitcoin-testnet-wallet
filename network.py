"""
Steps 2 and 8: the only parts that talk to the outside world.
Uses public testnet Esplora-compatible APIs (no API key needed). Two
mirrors are used (Blockstream + mempool.space) so a slow/unavailable
server on one doesn't block the whole flow.
Docs: https://github.com/Blockstream/esplora/blob/master/API.md
"""
import time
import requests

# Primary + fallback mirror, same Esplora API shape.
API_BASES = [
    "https://blockstream.info/testnet/api",
    "https://mempool.space/testnet/api",
]

# Each "round" tries every mirror once with this timeout, before waiting
# briefly and moving to the next (longer) round. This way a healthy mirror
# answers fast (<=8s), and we only wait longer if BOTH are genuinely down.
TIMEOUT_SCHEDULE = [8, 15]   # seconds per attempt, per round
ROUND_PAUSE = 1              # seconds to wait between rounds


def _request(method: str, path: str, data=None):
    last_error = None
    for round_idx, timeout in enumerate(TIMEOUT_SCHEDULE):
        for base in API_BASES:
            try:
                if method == "GET":
                    resp = requests.get(f"{base}{path}", timeout=timeout)
                else:
                    resp = requests.post(f"{base}{path}", data=data, timeout=timeout)

                if resp.status_code >= 500:
                    # server-side error (502/503/504...) - transient, try next mirror
                    last_error = f"{resp.status_code} from {base}"
                    continue

                if method == "GET":
                    resp.raise_for_status()  # 4xx here is a real error (bad address etc), not transient
                return resp
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                last_error = e
                continue  # try the next mirror immediately, don't wait
            except requests.exceptions.HTTPError:
                raise  # a real 4xx client error won't be fixed by retrying
        if round_idx < len(TIMEOUT_SCHEDULE) - 1:
            time.sleep(ROUND_PAUSE)
    raise RuntimeError(f"Both API mirrors failed after retries: {last_error}")


def get_utxos(address: str) -> list:
    """Return all unspent outputs for an address."""
    return _request("GET", f"/address/{address}/utxo").json()


def get_raw_tx_hex(txid: str) -> str:
    """Fetch the raw hex of a previous tx (sometimes needed to read its
    scriptPubKey when building inputs)."""
    return _request("GET", f"/tx/{txid}/hex").text.strip()


def get_tx_history(address: str, limit: int = 15) -> list:
    """Return recent confirmed + mempool transactions touching this address,
    newest first. Used for the transaction history panel in the UI."""
    txs = _request("GET", f"/address/{address}/txs").json()[:limit]

    history = []
    for tx in txs:
        received = sum(o["value"] for o in tx["vout"] if o.get("scriptpubkey_address") == address)
        sent = sum(i["prevout"]["value"] for i in tx["vin"]
                   if i.get("prevout", {}).get("scriptpubkey_address") == address)
        net = received - sent
        history.append({
            "txid": tx["txid"],
            "confirmed": tx["status"]["confirmed"],
            "block_time": tx["status"].get("block_time"),
            "net_sat": net,
            "fee_sat": tx.get("fee", 0),
            "explorer_url": f"https://mempool.space/testnet/tx/{tx['txid']}",
        })
    return history


def get_fee_estimate() -> dict:
    """Recommended sat/vByte fee rates by confirmation target."""
    return _request("GET", "/fee-estimates").json()


def broadcast_tx(raw_tx_hex: str) -> str:
    """Step 8: broadcast to the Bitcoin (testnet) network. Returns txid."""
    resp = _request("POST", "/tx", data=raw_tx_hex)
    if resp.status_code != 200:
        raise RuntimeError(f"Broadcast rejected: {resp.text}")
    txid = resp.text.strip()
    if len(txid) != 64:
        raise RuntimeError(f"Broadcast returned an invalid txid: {txid!r}")
    try:
        bytes.fromhex(txid)
    except ValueError as exc:
        raise RuntimeError(f"Broadcast returned an invalid txid: {txid!r}") from exc
    return txid
