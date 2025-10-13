#!/usr/bin/env python3
"""
engine_fcu_withdrawal.py

Requirements:
    pip install requests pyjwt

What it does:
 - Reads JWT secret from a file (raw bytes / utf-8).
 - Queries eth RPC for latest block (to get head block hash).
 - Builds a payloadAttributesV2 including a single withdrawal of 1000 ETH
   (converted to Gwei, as required by the spec).
 - Sends engine_forkchoiceUpdatedV3 with safe/finalized set to the null hash.
 - Signs a fresh JWT per engine request; iat is set to current time.
"""

import time
import json
import requests
import jwt      # PyJWT
import os
import sys
from pathlib import Path

# ----------------- CONFIG -----------------
# Edit these values to match your setup:
ETH_RPC_URL = os.getenv("ETH_RPC_URL", "http://127.0.0.1:8545")        # JSON-RPC (eth_* methods)
ENGINE_API_URL = os.getenv("ENGINE_API_URL", "http://localhost:8551")  # Engine API (engine_* methods)
JWT_SECRET_FILE = os.getenv("JWT_SECRET_FILE", "./jwt/jwt.hex")  # file containing secret
# The address that receives the withdrawal (20 byte hex addr)
WITHDRAW_TO_ADDRESS = os.getenv("WITHDRAW_TO_ADDRESS", "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b")
# Optional: set a suggested fee recipient (must be 0x...40 hex chars)
SUGGESTED_FEE_RECIPIENT = os.getenv("SUGGESTED_FEE_RECIPIENT", WITHDRAW_TO_ADDRESS)
# Optional JWT expiry (seconds). If you want only iat, set to None. Many engines accept a short exp.
JWT_EXP_SECONDS = 60
# ------------------------------------------

NULL_HASH_32 = "0x" + "00" * 32

def headers(secret_bytes):
    # Create JWT with iat. Should be issued recently (within a minute)
    iat = int(time.time())
    token = jwt.encode({"iat": iat, "exp": iat + 36000}, secret_bytes, algorithm="HS256")

    # Use in requests
    headers = {"Content-Type": "application/json",
            "Authorization": f"Bearer {token}"}
    
    return headers

def read_text_file_strip(path: Path) -> str:
    txt = path.read_text(encoding="utf-8").strip()
    # If file contains newline-separated data, take first non-empty line
    for line in txt.splitlines():
        if line.strip():
            return line.strip()
    return txt.strip()

def make_jwt(secret, extra_claims=None, exp_seconds=JWT_EXP_SECONDS):
    now = int(time.time())
    payload = {"iat": now}
    # include exp if requested (recommended)
    if exp_seconds is not None:
        payload["exp"] = now + int(exp_seconds)
    if extra_claims:
        payload.update(extra_claims)
    token = jwt.encode(payload, secret, algorithm="HS256")
    # PyJWT returns str in pyjwt>=2, else bytes.
    if isinstance(token, bytes):
        token = token.decode()
    return token

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

def hex_uint(n):
    """Return hex representation without leading 'L' etc."""
    if n == 0:
        return "0x0"
    return hex(n)

def main():
    # basic checks
    if not os.path.exists(JWT_SECRET_FILE):
        print(f"JWT secret file not found: {JWT_SECRET_FILE}", file=sys.stderr)
        sys.exit(2)

    # read secret
    jwt_token = read_text_file_strip(Path(JWT_SECRET_FILE))
    secret_bytes = bytes.fromhex(jwt_token)

    # 1) Query latest block hash from eth RPC
    # We'll call eth_getBlockByNumber with "latest" and include minimal fields
    # eth_getBlockByNumber returns an object including "hash"
    try:
        latest_block = rpc_request(ETH_RPC_URL, "eth_getBlockByNumber", ["latest", False])
    except Exception as e:
        print("Failed to query latest block:", e, file=sys.stderr)
        sys.exit(3)

    if not latest_block or "hash" not in latest_block:
        print("Could not obtain head block hash from eth_getBlockByNumber", file=sys.stderr)
        sys.exit(4)

    head_hash = latest_block["hash"]
    print("head block hash:", head_hash)

    # 2) Build forkchoiceState with safe/finalized = null hash
    forkchoice_state = {
        "headBlockHash": head_hash,
        "safeBlockHash": NULL_HASH_32,
        "finalizedBlockHash": NULL_HASH_32
    }

    # 3) Build payloadAttributesV2 with one withdrawal of 1000 ETH
    # Specifications: withdrawal amount is in Gwei (uint64). 1 ETH = 1e9 Gwei.
    # 1000 ETH -> 1000 * 1e9 = 1e12 Gwei
    eth_amount = 1000
    gwei_per_eth = 10 ** 9
    amount_gwei = eth_amount * gwei_per_eth  # integer 1_000_000_000_000
    # convert to hex string as required by spec
    amount_hex = hex_uint(amount_gwei)

    # Many implementations expect strings in hex-form for timestamp and numeric fields.
    timestamp = int(time.time())
    # timestamp must be hex per spec (0x...)
    timestamp_hex = hex_uint(timestamp)

    # prevRandao is 32-byte hex value. For testing we can set to null or a random value.
    prev_randao = NULL_HASH_32

    # Withdrawal structure per spec: fields are hex-strings for numeric fields
    withdrawal = {
        "index": hex_uint(0),            # choose index 0 (example)
        "validatorIndex": hex_uint(0),   # choose validatorIndex 0 (example)
        "address": WITHDRAW_TO_ADDRESS,  # 0x...20 bytes
        "amount": amount_hex             # amount in Gwei as hex string
    }

    payload_attributes = {
        "timestamp": timestamp_hex,
        "prevRandao": prev_randao,
        "suggestedFeeRecipient": SUGGESTED_FEE_RECIPIENT,
        "withdrawals": [withdrawal],
        "parentBeaconBlockRoot": NULL_HASH_32
    }

    # 4) Sign JWT with fresh iat

    exchange_capabilities = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "engine_exchangeCapabilities",
        "params": [[]]
    }

    print("test")
    r = requests.post(ENGINE_API_URL, headers=headers(secret_bytes), json=exchange_capabilities)
    try:
        r.raise_for_status()
    except Exception as e:
        print("Engine API HTTP error:", e, file=sys.stderr)
        print("response status:", r.status_code, "body:", r.text, file=sys.stderr)
        sys.exit(5)
    print("done")
    # 5) Call engine_forkchoiceUpdatedV3
    # params: [forkchoiceState, payloadAttributes | null]
    request_body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "engine_forkchoiceUpdatedV3",
        "params": [forkchoice_state, payload_attributes]
    }

    print("sending engine_forkchoiceUpdatedV3 ...")
    r = requests.post(ENGINE_API_URL, json=request_body, headers=headers(secret_bytes))
    try:
        r.raise_for_status()
    except Exception as e:
        print("Engine API HTTP error:", e, file=sys.stderr)
        print("response status:", r.status_code, "body:", r.text, file=sys.stderr)
        sys.exit(5)

    resp = r.json()
    print("engine_forkchoiceUpdatedV3 response:")
    print(json.dumps(resp, indent=2))

    # 1. Extract payloadId
    payload_id = resp.get("result", {}).get("payloadId")
    if not payload_id:
        print("No payloadId returned by forkchoiceUpdatedV3", file=sys.stderr)
        sys.exit(6)

    time.sleep(4)

    # 2. Call engine_getPayloadV3
    print(f"Fetching payload with payloadId={payload_id}")
    get_payload_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "engine_getPayloadV3",
        "params": [payload_id]
    }
    r2 = requests.post(ENGINE_API_URL, json=get_payload_req, headers=headers(secret_bytes))
    r2.raise_for_status()
    payload_resp = r2.json()
    print("engine_getPayloadV3 response:")
    print(json.dumps(payload_resp, indent=2))

    result = payload_resp.get("result")
    if not result or not result.get("executionPayload"):
        print("No payload result in engine_getPayloadV3", file=sys.stderr)
        sys.exit(7)

    payload = result.get("executionPayload")

    # 3. Call engine_newPayloadV4 with the payload
    new_payload_req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "engine_newPayloadV4",
        "params": [payload, [], NULL_HASH_32, []]
    }

    print(new_payload_req)
    r3 = requests.post(ENGINE_API_URL, json=new_payload_req, headers=headers(secret_bytes))
    r3.raise_for_status()
    new_payload_resp = r3.json()
    print("engine_newPayloadV4 response:")
    print(json.dumps(new_payload_resp, indent=2))

    status = new_payload_resp.get("result", {}).get("status")
    if status != "VALID":
        print(f"newPayload returned non-VALID status: {status}", file=sys.stderr)

    # 4. Update forkchoice with new head block hash
    block_hash = payload.get("blockHash")
    if not block_hash:
        print("No blockHash in payload result", file=sys.stderr)
        sys.exit(8)

    final_forkchoice_state = {
        "headBlockHash": block_hash,
        "safeBlockHash": NULL_HASH_32,
        "finalizedBlockHash": NULL_HASH_32
    }

    final_fcu_req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "engine_forkchoiceUpdatedV3",
        "params": [final_forkchoice_state, None]
    }
    r4 = requests.post(ENGINE_API_URL, json=final_fcu_req, headers=headers(secret_bytes))
    r4.raise_for_status()
    final_resp = r4.json()
    print("Final engine_forkchoiceUpdatedV3 response:")
    print(json.dumps(final_resp, indent=2))




if __name__ == "__main__":
    main()
