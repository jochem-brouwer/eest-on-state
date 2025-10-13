# mitm_capture.py
# mitmproxy addon: capture engine_newPayload and engine_forkchoiceUpdated (without payloadAttributes)
# Writes one JSON-RPC request per line to OUTPUT_FILE (NDJSON).

from mitmproxy import http
import json
import os
import time
from typing import Optional

# Config: path to append captured requests
OUTPUT_FILE = os.getenv("MITM_CAPTURE_OUTPUT", f"./captured_engine_requests_{int(time.time())}.ndjson")

def _safe_load_json(text: bytes) -> Optional[dict]:
    try:
        # requests may contain bytes; decode as utf-8
        return json.loads(text.decode("utf-8"))
    except Exception:
        return None

def _is_target_request(req_obj: dict) -> bool:
    """
    Return True if this JSON-RPC request should be captured.
    - engine_newPayload* -> capture
    - engine_forkchoiceUpdated* with params[1] == None -> capture
    """
    if not isinstance(req_obj, dict):
        return False
    method = req_obj.get("method")
    params = req_obj.get("params", [])
    if not isinstance(method, str):
        return False

    # newPayload variants
    if method.startswith("engine_newPayload"):
        return True

    # forkchoiceUpdated variants; capture only when payloadAttributes param is null/None
    if method.startswith("engine_forkchoiceUpdated"):
        # params is expected to be a list: [forkchoiceState, payloadAttributes | null]
        if isinstance(params, list) and len(params) >= 2:
            # JSON null -> Python None
            if params[1] is None:
                return True

    return False

def _append_line(obj: dict):
    # Append compact JSON on a single line
    line = json.dumps(obj, separators=(",", ":"))
    # Ensure directory exists
    try:
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    except Exception:
        # if dirname is '', ignore
        pass
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def request(flow: http.HTTPFlow) -> None:
    """
    mitmproxy hook for every client request.
    """
    # Only inspect application/json bodies (but still try to parse if content-type missing)
    content_type = flow.request.headers.get("Content-Type", "")
    body_bytes = flow.request.raw_content or b""

    # Quick reject if no body
    if not body_bytes:
        return

    # Try to parse JSON-RPC body
    req_obj = _safe_load_json(body_bytes)
    if req_obj is None:
        return

    try:
        if _is_target_request(req_obj):
            # Add a small metadata field (timestamp) if you like — optional.
            captured = {
                "captured_at": int(time.time()),
                "request": req_obj
            }
            # Flattened output: write only the JSON-RPC request itself (as user requested).
            # If you prefer the metadata wrapper, change to _append_line(captured)
            _append_line(req_obj)
            # Optionally, log to mitmconsole
            flow.request.headers["x-mitm-captured"] = "1"
            print(f"[mitm_capture] captured {req_obj.get('method')} -> {OUTPUT_FILE}")
    except Exception as e:
        # Don't break proxy on errors; print trace for debugging.
        print(f"[mitm_capture] error processing request: {e}")