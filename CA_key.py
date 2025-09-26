#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Sep 25 09:13:34 2025

@author: cslinux
"""

import subprocess
import os

def run_cmd(cmd):
    print(f"[*] Running: {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def generate_certs():
    # Skip if certs already exist
    if all(os.path.exists(f) for f in ["ca.crt", "server.crt", "client.crt"]):
        print("[*] Certificates already exist. Skipping generation.")
        return

    # 1. Create a CA key and self-signed certificate
    run_cmd("openssl req -new -x509 -days 365 -nodes -subj \"/CN=MytCTesA\" -out ca.crt -keyout ca.key")

    # 2. Create server key and CSR
    run_cmd("openssl genrsa -out server.key 2048")
    run_cmd("openssl req -new -key server.key -subj \"/CN=localhost\" -out server.csr")

    # 3. Sign server cert with CA
    run_cmd("openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365")

    # 4. Create client key and CSR
    run_cmd("openssl genrsa -out client.key 2048")
    run_cmd("openssl req -new -key client.key -subj \"/CN=client\" -out client.csr")

    # 5. Sign client cert with CA
    run_cmd("openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365")

    print("[*] Certificates and keys generated successfully!")

if __name__ == "__main__":
    generate_certs()
