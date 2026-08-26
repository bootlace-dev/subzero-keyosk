import socket
import ssl
import json
import time

test_endpoints = [
    # (host, port, use_ssl)
    ("testnet4.aranguren.org", 51002, True),
    ("testnet4.aranguren.org", 51001, False),
    ("testnet4.mempool.space", 50002, True),
    ("testnet4.mempool.space", 40002, True),
    ("mempool.space", 40002, True),
    ("testnet4.electrumx.online", 50002, True),
    ("testnet4.electrumx.online", 50001, False),
    ("t4.electrum.io", 50002, True),
    ("electrum.testnet4.mempool.space", 50002, True),
    ("fulcrum.testnet4.freshelectrum.net", 50002, True),
    ("testnet4-electrum.blockstream.info", 50002, True),
    ("blockstream.info", 993, True),
    ("testnet.aranguren.org", 51002, True),
    ("testnet.aranguren.org", 51001, False),
    ("electrum.blockstream.info", 60002, True),
    ("electrum.blockstream.info", 60001, False),
]

print(f"{'HOST':<35} | {'PORT':<5} | {'SSL':<5} | {'LATENCY':<7} | {'STATUS / VERSION'}")
print("-" * 80)

for host, port, use_ssl in test_endpoints:
    start = time.time()
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=2.5) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as s:
                    req = json.dumps({"id": 1, "method": "server.version", "params": ["probe", "1.4"]}) + "\n"
                    s.sendall(req.encode())
                    resp = s.recv(1024).decode().strip()
                    lat = f"{(time.time() - start)*1000:.0f}ms"
                    print(f"{host:<35} | {port:<5} | {'YES':<5} | {lat:<7} | [OK] {resp}")
        else:
            with socket.create_connection((host, port), timeout=2.5) as s:
                req = json.dumps({"id": 1, "method": "server.version", "params": ["probe", "1.4"]}) + "\n"
                s.sendall(req.encode())
                resp = s.recv(1024).decode().strip()
                lat = f"{(time.time() - start)*1000:.0f}ms"
                print(f"{host:<35} | {port:<5} | {'NO':<5} | {lat:<7} | [OK] {resp}")
    except Exception as e:
        print(f"{host:<35} | {port:<5} | {str(use_ssl):<5} | {'FAIL':<7} | [ERROR] {e}")
