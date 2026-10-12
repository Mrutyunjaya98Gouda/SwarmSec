#!/usr/bin/env python3
"""
SwarmSec Local Server Runner
Starts the Registrar and 3 Nodes locally without needing Docker.
"""

import os
import subprocess
import time


def run():
    print("Starting SwarmSec network locally...")
    
    # Base environment
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    
    # 1. Start Registrar (optional: can be disabled if pointing to a remote registrar)
    registrar = None
    remote_registrar = os.environ.get("REGISTRAR_URL")
    
    if not remote_registrar:
        registrar_cmd = [
            "uvicorn", "swarmsec.registrar.app:app", 
            "--host", "0.0.0.0",
            "--port", "8000", 
            "--ssl-keyfile", "certs/registrar.key", 
            "--ssl-certfile", "certs/registrar.pem"
        ]
        registrar = subprocess.Popen(registrar_cmd, env=env)
        # Wait for registrar to start
        time.sleep(2)
        effective_registrar_url = "https://localhost:8000"
    else:
        print(f"Using remote Registrar at: {remote_registrar}")
        effective_registrar_url = remote_registrar

    # 2. Start Nodes
    nodes = []
    # If run as peer worker node on friend machine, NODE_PORT can be customized
    custom_port = os.environ.get("NODE_PORT")
    ports = [int(custom_port)] if custom_port else [8001, 8002, 8003]
    extra_peers = [p.strip() for p in os.environ.get("EXTRA_PEERS", "").split(",") if p.strip()]

    for i, port in enumerate(ports):
        node_num = int(os.environ.get("NODE_NUM", i + 1))
        peer_ports = [p for p in ports if p != port]
        local_peers = [f"https://localhost:{p}" for p in peer_ports]
        all_peers = local_peers + extra_peers
        peers_str = ",".join(all_peers)
        
        node_env = env.copy()
        node_env.update({
            "REGISTRAR_URL": effective_registrar_url,
            "PEERS": peers_str,
            "TLS_CA_PATH": "certs/ca.pem",
            "TLS_CERT_PATH": f"certs/node{node_num}.pem",
            "TLS_KEY_PATH": f"certs/node{node_num}.key",
            # Isolate per-node SQLite files to avoid DB collision (see rate_limit.py / app.py)
            "SWARMSEC_NODE_STATE_DB": f".swarmsec_node{node_num}_state.db",
            "SWARMSEC_REPLAY_DB": f".swarmsec_replay_node{node_num}.db",
        })
        
        node_cmd = [
            "uvicorn", "swarmsec.node.app:app", 
            "--host", "0.0.0.0",
            "--port", str(port), 
            "--ssl-keyfile", f"certs/node{node_num}.key", 
            "--ssl-certfile", f"certs/node{node_num}.pem"
        ]
        
        node_proc = subprocess.Popen(node_cmd, env=node_env)
        nodes.append(node_proc)
        
    print("\n✅ All servers started successfully!")
    print("  - Registrar: https://localhost:8000")
    print("  - Node 1:    https://localhost:8001")
    print("  - Node 2:    https://localhost:8002")
    print("  - Node 3:    https://localhost:8003")
    print("\nPress Ctrl+C to shut down the network.\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down servers...")
        if registrar:
            registrar.terminate()
        for n in nodes:
            n.terminate()
        print("Shutdown complete.")

if __name__ == "__main__":
    run()
