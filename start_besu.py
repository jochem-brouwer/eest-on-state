import subprocess
from pathlib import Path
import os
import shutil

# Code inspired from https://github.com/NethermindEth/gas-benchmarks
container_name = "besu-bench"
chain="mainnet"
snapshot_dir = Path("snapshot")
merged_dir = Path("overlay-merged")
upper_dir  = Path("overlay-upper")
work_dir   = Path("overlay-work")

def ensure_jwt(jwt_dir: Path) -> Path:
    jwt_dir.mkdir(parents=True, exist_ok=True)
    jwt = jwt_dir / "jwt.hex"
    if not jwt.exists(): jwt.write_text(os.urandom(32).hex())
    return jwt
jwt_path = ensure_jwt(Path("jwt"))

def stop_and_remove_container(name: str):
    subprocess.run(["docker", "rm", "-f", name], check=False)

def run(cmd, cwd=None, env=None, check=True):
    print("\n[RUN] " + " ".join(cmd))
    return subprocess.run(cmd, cwd=cwd, env=env, check=check)

def start_besu_container(chain: str, db_dir: Path, jwt_path: Path,
                               rpc_port=8545, engine_port=8551, name=container_name) -> str:
    cmd = [
        "docker", "run", "-d",
        "--name", name,
        "-p", f"{rpc_port}:{rpc_port}",
        "-p", f"{engine_port}:{engine_port}",  
        "-v", f"{str(db_dir.resolve())}:/db",
        "-v", f"{str(jwt_path.parent.resolve())}:/jwt:ro",
        "-e", "BESU_USER_NAME=root",
        "--user", "root",
        "hyperledger/besu",
        "--rpc-http-api", "ETH,NET,WEB3,ADMIN,DEBUG,TRACE,TXPOOL",
        "--rpc-http-enabled",
        "--rpc-http-host", "0.0.0.0",
        "--rpc-http-port", "8545",
        "--engine-rpc-enabled",
        "--engine-jwt-secret", "/jwt/jwt.hex",
        "--engine-rpc-port", str(engine_port),
        #"--network", str(chain),
        "--target-gas-limit", "60000000",
        "--data-path", "/db",
        "--max-peers", "0",
        "--logging", "INFO",
    ]
    cp = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, text=True)
    return cp.stdout.strip()

def ensure_overlay_mount(lower: Path, upper: Path, work: Path, merged: Path):
    lower = lower.resolve(); upper = upper.resolve(); work = work.resolve(); merged = merged.resolve()
    if not lower.exists() or not any(lower.iterdir()):
        raise RuntimeError(f"Lower dir {lower} missing or empty; download snapshot first.")
    upper.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    merged.mkdir(parents=True, exist_ok=True)
    mount_opts = f"lowerdir={lower},upperdir={upper},workdir={work}"
    cmd = ["mount", "-t", "overlay", "overlay", "-o", mount_opts, str(merged)]
    if hasattr(os, "geteuid") and os.geteuid() != 0 and shutil.which("sudo"):
        cmd = ["sudo"] + cmd
    run(cmd)

stop_and_remove_container(container_name)
ensure_overlay_mount(lower=snapshot_dir, upper=upper_dir, work=work_dir, merged=merged_dir)
start_besu_container(
        chain=chain,
        db_dir=merged_dir,
        jwt_path=jwt_path,
        rpc_port=8545,
        engine_port=8551,
        name=container_name,
    )