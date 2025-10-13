#!/usr/bin/env python3
"""
Send flattened engine newPayload requests from test_output/engine_requests.txt to an Engine API,
timing each request and then sending a forkchoiceUpdated using the blockHash from the payload.

Usage:
    python3 send_payloads_and_fcu.py \
        --engine-url http://localhost:8551 \
        --jwt-file jwt/jwt.hex \
        --anchor-file anchor_blockhash.hex \
        --requests-file test_output/engine_requests.txt

Defaults assume engine at http://localhost:8551 and paths shown above.
"""

import argparse
import json
import time
from pathlib import Path
import csv
import sys
import jwt  # pip install pyjwt

try:
    import requests
except Exception:
    print("This script requires the 'requests' library. Install with: pip install requests")
    sys.exit(1)


def read_text_file_strip(path: Path) -> str:
    txt = path.read_text(encoding="utf-8").strip()
    # If file contains newline-separated data, take first non-empty line
    for line in txt.splitlines():
        if line.strip():
            return line.strip()
    return txt.strip()


def validate_newpayload_response(resp_json: dict) -> (bool, str):
    """
    Typical engine_newPayload* result shape:
    { "result": { "status": "VALID" } } or { "result": { "status": "INVALID", "validationError": "..." } }
    Some implementations may return the status directly under result.
    Return (ok, status_string)
    """
    if not isinstance(resp_json, dict):
        return False, "non-json-result"

    result = resp_json.get("result")
    if isinstance(result, dict):
        status = result.get("status") or result.get("payloadStatus") or result.get("payload_status")
        # If it's nested like payloadStatus
        if isinstance(status, dict):
            status = status.get("status")
        if status:
            status_str = str(status)
            ok = status_str.upper().startswith("VALID") or status_str.upper().startswith("ACCEPT")
            return ok, status_str
    # older clients may return {'status': '...'} at top-level:
    top_status = resp_json.get("status")
    if top_status:
        s = str(top_status)
        ok = s.upper().startswith("VALID") or s.upper().startswith("ACCEPT")
        return ok, s
    # fallback: check for result == "VALID"
    if resp_json.get("result") in ("VALID", "ACCEPTED"):
        return True, str(resp_json.get("result"))
    return False, json.dumps(resp_json)[:200]


def validate_fcu_response(resp_json: dict) -> (bool, str):
    """
    engine_forkchoiceUpdatedV1 typically returns { "result": { "payloadStatus": { "status": "VALID", ... } } }
    Some clients return { "result": { "status": "VALID" } } — handle a few variants.
    """
    if not isinstance(resp_json, dict):
        return False, "non-json-result"

    result = resp_json.get("result", {})
    # If payloadStatus present:
    payload_status = result.get("payloadStatus") or result.get("payload_status")
    if isinstance(payload_status, dict):
        status = payload_status.get("status")
        if status:
            ok = str(status).upper().startswith("VALID") or str(status).upper().startswith("ACCEPT")
            return ok, str(status)
    # If result directly has status:
    status = result.get("status")
    if status:
        ok = str(status).upper().startswith("VALID") or str(status).upper().startswith("ACCEPT")
        return ok, str(status)
    # Some nodes might return result as a status string:
    if isinstance(result, str):
        ok = result.upper().startswith("VALID") or result.upper().startswith("ACCEPT")
        return ok, result
    return False, json.dumps(resp_json)[:200]

def headers(secret_bytes):
    # Create JWT with iat. Should be issued recently (within a minute)
    iat = int(time.time())
    token = jwt.encode({"iat": iat, "exp": iat + 36000}, secret_bytes, algorithm="HS256")

    # Use in requests
    headers = {"Content-Type": "application/json",
            "Authorization": f"Bearer {token}"}
    
    return headers

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--engine-url", default="http://localhost:8551", help="Engine API base URL (HTTP).")
    p.add_argument("--jwt-file", default="jwt/jwt.hex", help="Path to jwt token file (hex).")
    p.add_argument("--anchor-file", default="anchor_blockhash.hex", help="Path to anchor blockhash file.")
    p.add_argument("--requests-file", default="test_output/engine_requests.txt", help="Path to flattened requests file.")
    p.add_argument("--output-dir", default="test_output", help="Directory for logs/output.")
    p.add_argument("--timeout", type=float, default=30.0, help="HTTP request timeout in seconds.")
    args = p.parse_args()

    engine_url = args.engine_url.rstrip("/")
    jwt_path = Path(args.jwt_file)
    anchor_path = Path(args.anchor_file)
    requests_path = Path(args.requests_file)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not jwt_path.exists():
        print(f"JWT file not found: {jwt_path}")
        sys.exit(2)
    if not anchor_path.exists():
        print(f"Anchor blockhash file not found: {anchor_path}")
        sys.exit(2)
    if not requests_path.exists():
        print(f"Requests file not found: {requests_path}")
        sys.exit(2)

    jwt_token = read_text_file_strip(jwt_path)
    anchor_hash = read_text_file_strip(anchor_path)

    secret_bytes = bytes.fromhex(jwt_token)

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "engine_exchangeCapabilities",
        "params": [[]]
    }

    r = requests.post(engine_url, headers=headers(secret_bytes), json=payload)

    # Send initial forkchoiceUpdated with anchor as head/safe/finalized
    initial_fcu = {
        "jsonrpc": "2.0",
        "id": int(time.time()),
        "method": "engine_forkchoiceUpdatedV1",
        "params": [
            {
                "headBlockHash": anchor_hash,
                "safeBlockHash": anchor_hash,
                "finalizedBlockHash": anchor_hash,
            },
            # payloadAttributes can be null/empty for this initial FCU
            None,
        ],
    }

    log_file = output_dir / "engine_run.log"
    csv_file = output_dir / "results.csv"

    def log(msg):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {msg}"
        print(line)
        with open(log_file, "a", encoding="utf-8") as lf:
            lf.write(line + "\n")

    log("Starting engine-run")
    log(f"Engine URL: {engine_url}")
    log(f"Using JWT: {jwt_path}  Anchor: {anchor_path}")
    log(f"Requests file: {requests_path}")

    # perform initial FCU
    try:
        start = time.perf_counter()
        r = requests.post(engine_url, headers=headers(secret_bytes), json=initial_fcu, timeout=args.timeout)
        duration = time.perf_counter() - start
        r.raise_for_status()
        resp = r.json()
        ok, status = validate_fcu_response(resp)
        log(f"Initial forkchoiceUpdated -> status={status}  ok={ok}  time_s={duration:.6f}")
        if not ok:
            log("WARNING: initial forkchoiceUpdated not VALID. Proceeding anyway.")
    except Exception as e:
        log(f"ERROR sending initial forkchoiceUpdated: {e}")
        log("Aborting.")
        sys.exit(3)

    # open results CSV
    csv_fields = [
        "index",
        "blockHash",
        "blockNumber_hex",
        "blockNumber_int",
        "gasLimit",
        "newPayload_status",
        "newPayload_time_s",
        "fcu_status",
        "fcu_time_s",
        "combined_time_s",
        "source_line_preview",
    ]
    with open(csv_file, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=csv_fields)
        writer.writeheader()

        first_fcu = True

        # iterate requests file line by line
        with open(requests_path, "r", encoding="utf-8") as rf:
            for idx, line in enumerate(rf, start=1):
                sline = line.strip()
                if not sline:
                    continue
                # parse the flattened JSON (should be the full engine request object)
                try:
                    req_obj = json.loads(sline)
                except Exception as e:
                    log(f"Skipping line {idx}: invalid JSON: {e}")
                    continue

                # Extract blockHash and blockNumber and gasLimit for reporting
                block_hash = None
                block_number_hex = None
                gas_limit = None
                try:
                    # the request might already be the full engine_newPayload rpc object or might be just the params[0]
                    if isinstance(req_obj, dict) and req_obj.get("method", "").startswith("engine_newPayload"):
                        params0 = None
                        if isinstance(req_obj.get("params"), list) and len(req_obj["params"]) > 0 and isinstance(req_obj["params"][0], dict):
                            params0 = req_obj["params"][0]
                        elif isinstance(req_obj.get("params"), dict):
                            params0 = req_obj["params"]
                        if params0:
                            block_hash = params0.get("blockHash")
                            block_number_hex = params0.get("blockNumber")
                            gas_limit = params0.get("gasLimit")
                    # fallback: if user stored only the params block as top-level
                    if not block_hash and isinstance(req_obj, dict):
                        block_hash = req_obj.get("blockHash")
                        block_number_hex = block_number_hex or req_obj.get("blockNumber")
                        gas_limit = gas_limit or req_obj.get("gasLimit")
                except Exception as e:
                    log(f"Warning extracting metadata for line {idx}: {e}")

                try:
                    # Send newPayload request
                    np_start = time.perf_counter()
                    rnp = requests.post(engine_url, headers=headers(secret_bytes), json=req_obj, timeout=args.timeout)
                    np_duration = time.perf_counter() - np_start
                    rnp.raise_for_status()
                    np_resp = rnp.json()
                    np_ok, np_status = validate_newpayload_response(np_resp)
                    log(f"[{idx}] newPayload -> status={np_status} ok={np_ok} time_s={np_duration:.6f}")
                except Exception as e:
                    np_ok = False
                    np_status = f"error:{e}"
                    np_duration = None
                    log(f"[{idx}] ERROR sending newPayload: {e}")
                    # still attempt FCU? We will continue but record failure.

                # Use block_hash from payload; if missing, attempt to get it from params or reject
                if not block_hash:
                    # try to pull from req_obj params
                    try:
                        if isinstance(req_obj, dict) and isinstance(req_obj.get("params"), list) and len(req_obj["params"]) > 0:
                            block_hash = req_obj["params"][0].get("blockHash")
                            block_number_hex = block_number_hex or req_obj["params"][0].get("blockNumber")
                            gas_limit = gas_limit or req_obj["params"][0].get("gasLimit")
                    except Exception:
                        pass

                if not block_hash:
                    log(f"[{idx}] ERROR: Could not determine blockHash for FCU. Skipping FCU for this payload.")
                    fcu_ok = False
                    fcu_status = "no-blockHash"
                    fcu_duration = None
                    combined = None
                else:
                    # send forkchoiceUpdated with head/safe/finalized = block_hash
                    fcu_body = {
                        "jsonrpc": "2.0",
                        "id": int(time.time() * 1000) % 2**31,
                        "method": "engine_forkchoiceUpdatedV1",
                        "params": [
                            {
                                "headBlockHash": block_hash,
                                "safeBlockHash": block_hash,
                                "finalizedBlockHash": block_hash,
                            },
                            None,
                        ],
                    }
                    try:
                        fcu_start = time.perf_counter()
                        rf = requests.post(engine_url, headers=headers(secret_bytes), json=fcu_body, timeout=args.timeout)
                        fcu_duration = time.perf_counter() - fcu_start
                        rf.raise_for_status()
                        rf_json = rf.json()
                        fcu_ok, fcu_status = validate_fcu_response(rf_json)
                        log(f"[{idx}] forkchoiceUpdated -> status={fcu_status} ok={fcu_ok} time_s={fcu_duration:.6f}")
                    except Exception as e:
                        fcu_ok = False
                        fcu_status = f"error:{e}"
                        fcu_duration = None
                        log(f"[{idx}] ERROR sending forkchoiceUpdated: {e}")

                    # combined time equals np_duration + fcu_duration if both present
                    combined = None
                    if isinstance(np_duration, (float, int)) and isinstance(fcu_duration, (float, int)):
                        combined = np_duration + fcu_duration

                # Write CSV row
                preview = (sline[:200] + "...") if len(sline) > 200 else sline
                try:
                    bn_int = int(block_number_hex, 16) if block_number_hex else None
                except Exception:
                    bn_int = None
                writer.writerow({
                    "index": idx,
                    "blockHash": block_hash,
                    "blockNumber_hex": block_number_hex,
                    "blockNumber_int": bn_int,
                    "gasLimit": gas_limit,
                    "newPayload_status": np_status,
                    "newPayload_time_s": f"{np_duration:.6f}" if isinstance(np_duration, float) else "",
                    "fcu_status": fcu_status,
                    "fcu_time_s": f"{fcu_duration:.6f}" if isinstance(fcu_duration, float) else "",
                    "combined_time_s": f"{combined:.6f}" if isinstance(combined, float) else "",
                    "source_line_preview": preview,
                })
                # flush to disk
                cf.flush()

    log("Done. Results written to:")
    log(f"  - {csv_file}")
    log(f"  - {log_file}")


if __name__ == "__main__":
    main()
