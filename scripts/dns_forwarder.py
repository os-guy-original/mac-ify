#!/usr/bin/env python3
"""Simple UDP DNS forwarder: 127.0.0.1:53 -> upstream DNS server.

c-ares in mac-ify curl hardcodes 127.0.0.1:53 as the DNS server (because
macOS curl's c-ares is configured to use SystemConfiguration for DNS
discovery, which our shim stubs out, leaving c-ares with the localhost
fallback). This forwarder bridges 127.0.0.1:53 to the real DNS server
found in /etc/resolv.conf.
"""
import socket, sys, os

def get_upstream():
    with open('/etc/resolv.conf') as f:
        for line in f:
            line = line.strip()
            if line.startswith('nameserver'):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]
    return '8.8.8.8'

def main():
    upstream = get_upstream()
    print(f"DNS forwarder: 127.0.0.1:53 -> {upstream}:53", file=sys.stderr)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('127.0.0.1', 53))
    except PermissionError:
        print("ERROR: need root to bind port 53. Try: sudo python3 dns_forwarder.py", file=sys.stderr)
        sys.exit(1)

    pending = {}  # client_addr -> (upstream_sock, timestamp)

    while True:
        try:
            data, client = s.recvfrom(4096)
        except KeyboardInterrupt:
            break

        # Forward to upstream
        us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        us.settimeout(5.0)
        try:
            us.sendto(data, (upstream, 53))
            resp, _ = us.recvfrom(4096)
            s.sendto(resp, client)
        except socket.timeout:
            pass
        finally:
            us.close()

if __name__ == '__main__':
    main()
