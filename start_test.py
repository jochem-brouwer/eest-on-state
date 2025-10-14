#!/usr/bin/env python3
"""
engine_fcu_gaslimit_tracker.py

Continuously drives the engine API sequence:
  engine_forkchoiceUpdatedV3 → engine_getPayloadV4 → engine_newPayloadV4
to push block production until the gas limit reaches (or goes below)
a target threshold.

It tracks the gasLimit progression in each new payload and stops if:
 - gas limit <= target (✅ success)
 - gas limit increases (❌ moving away)
 - gas limit stagnates for too many rounds (❌ stuck)

Requires:
    pip install requests pyjwt
"""

import time
import json
import requests
import jwt
import os
import sys
from pathlib import Path

# ----------------- CONFIG -----------------
ETH_RPC_URL = os.getenv("ETH_RPC_URL", "http://127.0.0.1:8545")
ENGINE_API_URL = os.getenv("ENGINE_API_URL", "http://localhost:8550")
JWT_SECRET_FILE = os.getenv("JWT_SECRET_FILE", "./jwt/jwt.hex")

WITHDRAW_TO_ADDRESS = os.getenv(
    "WITHDRAW_TO_ADDRESS",
    "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
)
SUGGESTED_FEE_RECIPIENT = os.getenv(
    "SUGGESTED_FEE_RECIPIENT",
    WITHDRAW_TO_ADDRESS
)

# JWT expiration in seconds
JWT_EXP_SECONDS = 60

# Target minimum gas limit goal
TARGET_GAS_LIMIT = 60_000_000  # set desired minimum
# Max rounds allowed with constant gas limit
MAX_STAGNANT_ROUNDS = 3

NULL_HASH_32 = "0x" + "00" * 32

# ----------------- HELPERS -----------------
def read_text_file_strip(path: Path) -> str:
    txt = path.read_text(encoding="utf-8").strip()
    for line in txt.splitlines():
        if line.strip():
            return line.strip()
    return txt.strip()

def make_jwt(secret_bytes, exp_seconds=JWT_EXP_SECONDS):
    now = int(time.time())
    payload = {"iat": now}
    if exp_seconds is not None:
        payload["exp"] = now + int(exp_seconds)
    token = jwt.encode(payload, secret_bytes, algorithm="HS256")
    return token.decode() if isinstance(token, bytes) else token

def headers(secret_bytes):
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {make_jwt(secret_bytes)}"
    }

def hex_uint(n):
    if n == 0:
        return "0x0"
    return hex(n)

def get_gas_limit_from_payload(payload):
    try:
        return int(payload["gasLimit"], 16)
    except Exception:
        return None

def rpc_request(url, method, params=None, id=1):
    if params is None:
        params = []
    req = {"jsonrpc": "2.0", "id": id, "method": method, "params": params}
    r = requests.post(url, json=req)
    r.raise_for_status()
    j = r.json()
    if "error" in j:
        raise RuntimeError(f"RPC error for {method}: {j['error']}")
    return j.get("result")

# ----------------- MAIN -----------------
def main():
    if not os.path.exists(JWT_SECRET_FILE):
        print(f"JWT secret file not found: {JWT_SECRET_FILE}", file=sys.stderr)
        sys.exit(2)

    jwt_token = read_text_file_strip(Path(JWT_SECRET_FILE))
    secret_bytes = bytes.fromhex(jwt_token)

    # Query latest head hash from eth RPC
    try:
        latest_block = rpc_request(ETH_RPC_URL, "eth_getBlockByNumber", ["latest", False])
    except Exception as e:
        print("Failed to query latest block:", e, file=sys.stderr)
        sys.exit(3)

    if not latest_block or "hash" not in latest_block:
        print("Could not obtain head block hash from eth_getBlockByNumber", file=sys.stderr)
        sys.exit(4)

    head_hash = latest_block["hash"]
    print("Initial head block hash:", head_hash)
    timestamp = int(latest_block["timestamp"], 16)

    # Prepare withdrawal
    eth_amount = 1000
    gwei_per_eth = 10 ** 9
    amount_gwei = eth_amount * gwei_per_eth
    amount_hex = hex_uint(amount_gwei)

    withdrawal = {
        "index": hex_uint(0),
        "validatorIndex": hex_uint(0),
        "address": WITHDRAW_TO_ADDRESS,
        "amount": amount_hex
    }

    payload_attributes_template = {
        "timestamp": hex_uint(timestamp + 1),
        "prevRandao": NULL_HASH_32,
        "suggestedFeeRecipient": SUGGESTED_FEE_RECIPIENT,
        "withdrawals": [withdrawal],
        "parentBeaconBlockRoot": NULL_HASH_32
    }

    # Loop until we reach gas limit target
    last_gas_limit = None
    stagnant_rounds = 0
    round_counter = 0

    while True:
        timestamp += 1
        round_counter += 1
        print(f"\n===== ROUND {round_counter} =====")

        # 1. Build forkchoice + payloadAttributes
        forkchoice_state = {
            "headBlockHash": head_hash,
            "safeBlockHash": NULL_HASH_32,
            "finalizedBlockHash": NULL_HASH_32
        }

        print(hex_uint(timestamp))

        payload_attributes = payload_attributes_template.copy()
        payload_attributes["timestamp"] = hex_uint(timestamp)

        fcu_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "engine_forkchoiceUpdatedV3",
            "params": [forkchoice_state, payload_attributes]
        }

        r = requests.post(ENGINE_API_URL, json=fcu_req, headers=headers(secret_bytes))
        r.raise_for_status()
        fcu_resp = r.json()

        payload_id = fcu_resp.get("result", {}).get("payloadId")
        if not payload_id:
            raise RuntimeError("No payloadId returned by engine_forkchoiceUpdatedV3")

        # 2. Get payload
        get_payload_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "engine_getPayloadV4",
            "params": [payload_id]
        }
        r2 = requests.post(ENGINE_API_URL, json=get_payload_req, headers=headers(secret_bytes))
        r2.raise_for_status()
        payload_resp = r2.json()
        payload = payload_resp.get("result", {}).get("executionPayload")

        if not payload:
            raise RuntimeError("No executionPayload in getPayloadV4 result")

        gas_limit = get_gas_limit_from_payload(payload)
        print(f"→ Payload gasLimit: {gas_limit:,}")

        # 3. Compare to previous round
        if last_gas_limit is not None:
            if gas_limit < last_gas_limit:
                raise RuntimeError(f"❌ Gas limit decreased ({last_gas_limit:,} → {gas_limit:,}), moving away from target.")
            elif gas_limit == last_gas_limit:
                stagnant_rounds += 1
                print(f"⚠️ Gas limit unchanged ({stagnant_rounds}/{MAX_STAGNANT_ROUNDS})")
                if stagnant_rounds >= MAX_STAGNANT_ROUNDS:
                    raise RuntimeError("❌ Gas limit stagnant for too long, aborting.")
            else:
                stagnant_rounds = 0  # gas decreased, good
        last_gas_limit = gas_limit

        # 4. Submit new payload
        new_payload_req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "engine_newPayloadV4",
            "params": [payload, [], NULL_HASH_32, []]
        }
        r3 = requests.post(ENGINE_API_URL, json=new_payload_req, headers=headers(secret_bytes))
        r3.raise_for_status()
        status = r3.json()["result"]["status"]
        print(f"engine_newPayloadV4 → status: {status}")
        if status != "VALID":
            raise RuntimeError(f"newPayload returned non-VALID status: {status}")

        # 5. Update forkchoice with new head block hash
        block_hash = payload["blockHash"]
        head_hash = block_hash

        final_fcu_req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "engine_forkchoiceUpdatedV3",
            "params": [{
                "headBlockHash": block_hash,
                "safeBlockHash": NULL_HASH_32,
                "finalizedBlockHash": NULL_HASH_32
            }, None]
        }

        r4 = requests.post(ENGINE_API_URL, json=final_fcu_req, headers=headers(secret_bytes))
        r4.raise_for_status()
        print("✅ Forkchoice updated to new head.")

        if gas_limit >= TARGET_GAS_LIMIT:
            print(f"✅ Reached target gas limit ({gas_limit:,} >= {TARGET_GAS_LIMIT:,})")
            break
    print("Gas limit ready and account has been funded, ready to start EEST tests!")



if __name__ == "__main__":
    main()
