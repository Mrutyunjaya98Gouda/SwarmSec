#!/usr/bin/env python3
"""
SwarmSec Local Server Runner
Starts the Registrar and 3 Nodes locally without needing Docker.
"""

import subprocess
import os
import time
import sys

def run():
    print("Starting SwarmSec network locally...")
    
    # Base environment
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    
    # 1. Start Registrar
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
    
    # 2. Start Nodes
    nodes = []
    ports = [8001, 8002, 8003]
    
    for i, port in enumerate(ports):
        node_num = i + 1
        peer_ports = [p for p in ports if p != port]
        peers_str = ",".join([f"https://localhost:{p}" for p in peer_ports])
        
        node_env = env.copy()
        node_env.update({
            "REGISTRAR_URL": "https://localhost:8000",
            "PEERS": peers_str,
            "TLS_CA_PATH": "certs/ca.pem",
            "TLS_CERT_PATH": f"certs/node{node_num}.pem",
            "TLS_KEY_PATH": f"certs/node{node_num}.key"
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
        registrar.terminate()
        for n in nodes:
            n.terminate()
        print("Shutdown complete.")

if __name__ == "__main__":
    run()
