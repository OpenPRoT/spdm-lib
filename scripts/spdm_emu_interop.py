#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""Run DMTF spdm-emu's requester against the poc-responder for each SPDM version.

usage: scripts/spdm_emu_interop.py [--port N] [--emu-dir DIR] [versions...]
Exit status is non-zero if any version fails.
"""
import argparse
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESPONDER = ROOT / "target/debug/examples/poc-responder"
CAPS = "CERT,CHAL,ENCRYPT,MAC,KEY_EX,HBEAT,KEY_UPD,CHUNK"


def port_open(port):
    with socket.socket() as s:
        s.settimeout(0.2)
        return s.connect_ex(("127.0.0.1", port)) == 0


def run_version(ver, port, emu_dir):
    # Fresh responder per version so no state carries over.
    resp = subprocess.Popen(
        [str(RESPONDER), "--port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        for _ in range(50):
            if port_open(port):
                break
            time.sleep(0.1)
        else:
            return False, "responder never listened"
        req = subprocess.run(
            ["./spdm_requester_emu", "--trans", "NONE", "--port", str(port),
             "--ver", ver, "--cap", CAPS, "--pqc_asym", "NONE", "--slot_count", "1",
             "--exe_conn", "DIGEST,CERT,CHAL,MEAS", "--exe_session", "NO_END"],
            cwd=emu_dir, capture_output=True, text=True, timeout=60,
        )
        return req.returncode == 0, req.stdout + req.stderr
    except subprocess.TimeoutExpired:
        return False, "requester timed out"
    finally:
        resp.terminate()
        try:
            resp.wait(timeout=5)
        except subprocess.TimeoutExpired:
            resp.kill()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=2323)
    ap.add_argument("--emu-dir", default="/home/wmarone/dmtf/spdm-emu/build/bin")
    ap.add_argument("versions", nargs="*", default=["1.2", "1.3", "1.4"])
    a = ap.parse_args()

    if port_open(a.port):
        sys.exit(f"port {a.port} already in use (stale poc-responder? pkill -x poc-responder)")

    # Not --all-features: libspdm rejects the feature-heavy responder build.
    subprocess.run(["cargo", "build", "-p", "spdm-examples", "--examples"],
                   cwd=ROOT, check=True)

    failed = []
    for ver in a.versions:
        ok, out = run_version(ver, a.port, a.emu_dir)
        print(f"[{'PASS' if ok else 'FAIL'}] SPDM {ver}")
        if not ok:
            failed.append(ver)
            print(out[-3000:])
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
