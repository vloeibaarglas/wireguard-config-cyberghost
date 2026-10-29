#!/usr/bin/env python3
"""
CyberGhost -> WireGuard config fetcher (non-official)

Talks to the CyberGhost private API:
  - base URL .......... https://v2-api.cyberghostvpn.com/v2
  - login ............. POST /my/account/jwt?language=en  -> {"jwt": ...}
  - device ............ POST /my/devices {"linuxApp": true, "machineName": ...}
                        -> {"token": ..., "tokenSecret": ...}
  - wireguard key ..... GET https://<server>.cg-dialup.net:1337/addKey
                        (HTTP Basic auth = device token:tokenSecret,
                         ?pubkey=<base64 public key>) -> full wg config text

Server types:
  traffic    -> /my/servers/filters/73 (countries), /74 (instances)
  streaming  -> /my/servers/filters/76 (services),  /72 (instances by content)
  torrent    -> /my/servers/filters/75 (countries), /71 (instances)

You supply two files from YOUR copy of the official CyberGhost Linux client:
  - the `cyberghostvpn` binary (--app-key-bin PATH) for the `x-app-key`
    (--app-key KEY | --app-key-file PATH | X_APP_KEY env var | prompt work too)
  - the TLS CA (--ca-cert PATH | X_CA_CERT), defaulting to
    ./wireguard/ca.crt next to that binary.
This repository ships neither value.

Usage:
    python3 cyberghost_wireguard.py --user U --password P --app-key KEY [--server-type traffic] [--country us] [--city miami]
    python3 cyberghost_wireguard.py --user U --password P --server-type streaming --service netflix [--country us]
    python3 cyberghost_wireguard.py --user U --password P --server-type torrent [--country de]
    python3 cyberghost_wireguard.py --user U --password P --list-countries
    python3 cyberghost_wireguard.py --user U --password P --list-services
    python3 cyberghost_wireguard.py --user U --password P --list-servers us

Output: prints a ready-to-use [Interface]/[Peer] config. Pipe to a file:
    ... > /etc/wireguard/cg.conf  (then: wg-quick up cg / import in WireSock/WireDock)
"""

import argparse
import base64
import getpass
import http.client as _http_client
import json
import os
import socket
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request

API_URL = "https://v2-api.cyberghostvpn.com/v2"
# Runtime-supplied `x-app-key` header value (never hardcoded).
# Resolved from --app-key / --app-key-file / X_APP_KEY env / prompt.
APP_KEY = None
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36")

# Legacy repo-local CA path (no longer shipped; kept as a last resort).
# Resolved at runtime from --ca-cert / X_CA_CERT or ./wireguard/ca.crt
# next to the --app-key-bin binary.
CA_CRT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wireguard", "ca.crt")
CA_CERT = None


def read_secret(prompt, mode="mask"):
    """Read a secret from the terminal.

    mode:
      mask   -> echo '*' per typed/pasted character (default; lets you see
                how many chars got through when pasting over SSH)
      hidden -> echo nothing (classic getpass behavior)
      show   -> echo the plaintext (do not use on shared screens)

    When stdin is not a TTY (piped input, tests) it falls back to a plain
    read, since there is nothing to echo to.
    """
    if mode == "hidden":
        return getpass.getpass(prompt)

    if mode == "show" or not sys.stdin.isatty():
        return input(prompt).strip()

    # masked input with '*': works on Linux/macOS over SSH, and on Windows
    if os.name == "nt":
        try:
            import msvcrt
        except ImportError:
            return getpass.getpass(prompt)
        sys.stdout.write(prompt)
        sys.stdout.flush()
        chars = []
        while True:
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                sys.stdout.write("\n")
                return "".join(chars)
            if ch == "\x03":  # Ctrl-C
                sys.stdout.write("\n")
                raise KeyboardInterrupt
            if ch in ("\b", "\x7f"):
                if chars:
                    chars.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue
            if ch in ("\x00", "\xe0"):  # function/arrow key prefix, skip it
                msvcrt.getwch()
                continue
            chars.append(ch)
            sys.stdout.write("*")
            sys.stdout.flush()
        return "".join(chars)

    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    chars = []
    try:
        tty.setcbreak(fd)
        sys.stdout.write(prompt)
        sys.stdout.flush()
        while True:
            ch = sys.stdin.read(1)
            if ch in ("\n", "\r"):
                sys.stdout.write("\n")
                break
            if ch in ("\x03", "\x04"):  # Ctrl-C / Ctrl-D
                sys.stdout.write("\n")
                raise KeyboardInterrupt
            if ch in ("\x7f", "\b"):  # backspace / DEL
                if chars:
                    chars.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue
            chars.append(ch)
            sys.stdout.write("*")
            sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return "".join(chars)


def _extract_key_from_binary(path):
    """Extract the x-app-key from the user's official client binary."""
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    ext = os.path.join(here, "extract", "extract_x_app_key.py")
    if not os.path.isfile(ext):
        raise SystemExit("Extractor not found at %s." % ext)
    spec = importlib.util.spec_from_file_location("extract_x_app_key", ext)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    try:
        return mod.extract_key(os.path.expanduser(path))
    except Exception as e:
        raise SystemExit("Key extraction from %r failed: %s" % (path, e))


def resolve_app_key(cli_value=None, file_value=None, bin_value=None):
    """Return the runtime `x-app-key` value (never hardcoded).

    Precedence: --app-key > X_APP_KEY env > --app-key-bin > X_APP_KEY_BIN
    env > --app-key-file > X_APP_KEY_FILE env > interactive prompt.
    Exits when no value is available.
    """
    if cli_value:
        return cli_value.strip()
    env = os.environ.get("X_APP_KEY")
    if env and env.strip():
        return env.strip()
    binpath = bin_value or os.environ.get("X_APP_KEY_BIN")
    if binpath and binpath.strip():
        return _extract_key_from_binary(binpath.strip())
    path = file_value or os.environ.get("X_APP_KEY_FILE")
    if path:
        with open(os.path.expanduser(path), encoding="utf-8") as f:
            val = f.read().strip()
        if val:
            return val
        raise SystemExit("App-key file %r is empty." % path)
    try:
        val = getpass.getpass("X app key (see extract/extract_x_app_key.py): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit("Aborted: no x-app-key supplied.")
    if not val:
        raise SystemExit("Aborted: no x-app-key supplied. "
                         "Use --app-key KEY, --app-key-bin PATH, or set X_APP_KEY.")
    return val


def resolve_ca_cert(cli_value=None, bin_value=None):
    """Locate the TLS CA for the addKey endpoint (never shipped).

    Precedence: --ca-cert > X_CA_CERT env > ./wireguard/ca.crt next to the
    --app-key-bin binary > repo-local wireguard/ca.crt. Exits when no
    readable CA is available.
    """
    for cand in (cli_value, os.environ.get("X_CA_CERT")):
        if cand and cand.strip():
            p = os.path.expanduser(cand.strip())
            if os.path.isfile(p):
                return p
            raise SystemExit("CA file not found: %r." % cand)
    binpath = bin_value or os.environ.get("X_APP_KEY_BIN")
    if binpath and binpath.strip():
        p = os.path.join(os.path.dirname(os.path.abspath(
            os.path.expanduser(binpath.strip()))), "wireguard", "ca.crt")
        if os.path.isfile(p):
            return p
    if os.path.isfile(CA_CRT):
        return CA_CRT
    raise SystemExit("Missing CA: pass --ca-cert PATH, set X_CA_CERT, or point "
                     "--app-key-bin at the unpacked client tree "
                     "(./wireguard/ca.crt next to the binary).")


class _NoSNIConnection(_http_client.HTTPSConnection):
    """TLS without SNI for SNI-filtering middleboxes (same cert, no hostname)."""
    def connect(self):
        self.sock = socket.create_connection((self.host, self.port),
                                             self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=None)


class _NoSNIHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_NoSNIConnection, req, context=self._context)


def _verify_cg_chain(der_cert, cafile):
    """Chain-check against CG's root without OpenSSL anchor strictness.

    Some OpenSSL builds reject the 2017 root (non-critical basicConstraints)
    as a trust anchor. Signature math doesn't vary by build: if CG's root
    didn't sign this leaf, reject. Raises ssl.SSLError on any mismatch.
    """
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import padding
    with open(cafile, "rb") as f:
        root = x509.load_pem_x509_certificate(f.read())
    leaf = x509.load_der_x509_certificate(der_cert)
    if leaf.issuer != root.subject:
        raise ssl.SSLCertVerificationError("leaf issuer != CG root subject")
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        valid = leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc
    except AttributeError:  # old cryptography: naive datetimes
        valid = (leaf.not_valid_before <= now.replace(tzinfo=None)
                 <= leaf.not_valid_after)
    if not valid:
        raise ssl.SSLCertVerificationError("leaf outside validity period")
    try:
        root.public_key().verify(
            leaf.signature, leaf.tbs_certificate_bytes,
            padding.PKCS1v15(), leaf.signature_hash_algorithm)
    except Exception as e:  # noqa: BLE001 — any failure means reject
        raise ssl.SSLCertVerificationError("leaf signature invalid: %s" % e)


def _manual_get(req, data, cafile, sni):
    """GET with CERT_NONE + manual CG-root check (strict-OpenSSL fallback)."""
    parts = urllib.parse.urlsplit(req.full_url)
    path = parts.path + ("?" + parts.query if parts.query else "")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    cls = _http_client.HTTPSConnection if sni else _NoSNIConnection
    conn = cls(parts.hostname, parts.port or 443, context=ctx)
    try:
        conn.request(req.get_method(), path, body=data,
                     headers=dict(req.header_items()))
        resp = conn.getresponse()
        der = conn.sock.getpeercert(binary_form=True)
        if not der:
            raise ssl.SSLCertVerificationError("no peer certificate")
        _verify_cg_chain(der, cafile)
        return resp.status, json.loads(resp.read().decode() or "{}")
    finally:
        conn.close()


def http(method, url, token=None, bearer=None, body=None, verify=None,
         sni=True):
    """Tiny requests-like helper using only stdlib."""
    if not APP_KEY:
        raise SystemExit("Missing x-app-key: pass --app-key KEY or --app-key-bin PATH, "
                         "set X_APP_KEY, or use --app-key-file PATH.")
    req = urllib.request.Request(url, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("x-app-key", APP_KEY)
    req.add_header("User-Agent", UA)
    if bearer:
        req.add_header("Authorization", "Bearer " + bearer)
    if token:  # HTTP Basic for the addKey helper
        raw = ("%s:%s" % token).encode()
        req.add_header("Authorization", "Basic " + base64.b64encode(raw).decode())
    data = json.dumps(body).encode() if body is not None else None
    ctx = None
    if verify is not None:
        ctx = ssl.create_default_context(cafile=verify)
        ctx.check_hostname = False  # addKey cert CN is the internal node name (no SAN)
    try:
        if not sni:
            opener = urllib.request.build_opener(_NoSNIHandler(context=ctx))
            with opener.open(req, data=data) as r:
                return r.status, json.loads(r.read().decode() or "{}")
        with urllib.request.urlopen(req, data=data, context=ctx) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.URLError as e:
        # urlopen wraps transport failures; HTTPError (bad status/auth) must
        # propagate, only certificate rejects get the manual fallback.
        if (verify is None or not isinstance(
                getattr(e, "reason", None), ssl.SSLCertVerificationError)):
            raise
        try:
            return _manual_get(req, data, verify, sni)
        except ImportError:
            raise e


def login(user, password):
    _, resp = http("POST", API_URL + "/my/account/jwt?language=en",
                   body={"userName": user, "password": password})
    jwt = resp.get("jwt")
    if not jwt:
        raise SystemExit("Login failed: %s" % json.dumps(resp))
    return jwt


def get_or_create_device(bearer, machine):
    # Reuse existing device if the name already exists
    _, devices = http("GET", API_URL + "/my/devices", bearer=bearer)
    if isinstance(devices, dict):
        devices = devices.get("devices", [])
    for d in devices or []:
        if d.get("name") == machine:
            return d["token"], d["tokenSecret"] if "tokenSecret" in d else d.get("secret")
    # Create a new device (counts against your device limit)
    _, d = http("POST", API_URL + "/my/devices",
                bearer=bearer, body={"linuxApp": True, "machineName": machine})
    if "token" not in d:
        raise SystemExit("Device creation failed: %s" % json.dumps(d))
    return d["token"], d["tokenSecret"]


def user_data(bearer):
    _, u = http("GET", API_URL + "/my/account?fields=(id,userName,location,activeProduct.plan)&language=en",
                bearer=bearer)
    plan = (u.get("activeProduct") or {}).get("plan") or {}
    loc = (u.get("location") or {})
    return {
        "id": u.get("id"),
        "plan_id": plan.get("id"),
        "lat": loc.get("latitude"),
        "lng": loc.get("longitude"),
    }


# ---------- server list endpoints (filter_protocol = openvpn | wireguard) ----------

def traffic_countries(bearer, ud, proto="wireguard"):
    url = (API_URL + "/my/servers/filters/73?filter_protocol=%s&filter_user_plans_id=%s"
           "&filter_user_id=%s&filter_user_latitude=%s&filter_user_longitude=%s"
           % (proto, ud["plan_id"], ud["id"], ud["lat"], ud["lng"]))
    _, r = http("GET", url, bearer=bearer)
    return r


def traffic_instances(bearer, ud, cc, proto="wireguard"):
    url = (API_URL + "/my/servers/filters/74?filter_protocol=%s&filter_country=%s"
           "&filter_user_id=%s&filter_user_latitude=%s&filter_user_longitude=%s"
           % (proto, cc.upper(), ud["id"], ud["lat"], ud["lng"]))
    _, r = http("GET", url, bearer=bearer)
    return r


def streaming_services(bearer, ud, proto="wireguard"):
    url = (API_URL + "/my/servers/filters/76?filter_protocol=%s&filter_user_plans_id=%s"
           % (proto, ud["plan_id"]))
    _, r = http("GET", url, bearer=bearer)
    return r


def streaming_instances(bearer, ud, content_id, proto="wireguard"):
    url = (API_URL + "/my/servers/filters/72?filter_protocol=%s&filter_user_plans_id=%s"
           "&filter_content_id=%s" % (proto, ud["plan_id"], content_id))
    _, r = http("GET", url, bearer=bearer)
    return r


def torrent_countries(bearer, ud, proto="wireguard"):
    url = (API_URL + "/my/servers/filters/75?filter_protocol=%s&filter_user_plans_id=%s"
           "&filter_user_latitude=%s&filter_user_longitude=%s"
           % (proto, ud["plan_id"], ud["lat"], ud["lng"]))
    _, r = http("GET", url, bearer=bearer)
    return r


def torrent_instances(bearer, ud, cc, proto="wireguard"):
    url = (API_URL + "/my/servers/filters/71?filter_protocol=%s&filter_country=%s"
           "&filter_user_plans_id=%s" % (proto, cc.upper(), ud["plan_id"]))
    _, r = http("GET", url, bearer=bearer)
    return r


def group_instances(rows, city=None):
    """Group raw instance rows (a flat list) into the shape the official client
    uses: {city: {index: {"id", "instance", "real", "userLoad"}}}.

    The /my/servers/filters/{71,72,74} endpoints return a *list* of server rows,
    each with 'city', 'displayName', 'totalusers' and 'Max_Users'; the official
    app groups them by city and strips the 'Nospyproxy' prefix from names.
    'real' is the server hostname (the script appends '.cg-dialup.net').
    """
    if isinstance(rows, dict):
        # already grouped (defensive; the API normally returns a list)
        return rows
    cities = {}
    for row in rows or []:
        c = (row.get("city") or "").lower()
        if city and c != city.lower():
            continue
        if c not in cities:
            cities[c] = {}
        idx = len(cities[c])
        try:
            load = round(int(row.get("totalusers") or 0)
                         / max(int(row.get("Max_Users") or 1), 1) * 100)
        except (TypeError, ValueError, ZeroDivisionError):
            load = 0
        name = row.get("displayName") or ""
        if "Nospyproxy" in name:
            name = name[10:]  # strip the 'Nospyproxy' prefix, as the app does
        cities[c][idx] = {
            "id": row.get("id"),
            "instance": name.lower(),
            "real": name.lower(),
            "userLoad": load,
        }
    return cities


def pick_server(data, city=None):
    # data[city][instanceKey] = {"id": ..., "instance": ..., "real": ..., "userLoad": ...}
    cities = data or {}
    if city:
        city = city.lower()
        city_key = next((k for k in cities if k.lower() == city), None)
        if city_key is None:
            raise SystemExit("City %r not found in: %s" % (city, ", ".join(cities)))
        cities = {city_key: cities[city_key]}
    ck = list(cities)[0]
    instances = cities[ck]
    ik = list(instances)[0]
    return instances[ik]["real"]


def gen_keys():
    """Generate a WireGuard keypair.

    Prefers the `wg` CLI if available; otherwise falls back to pure-Python
    X25519 via the `cryptography` package (produces identical keys, verified
    against `wg genkey`/`wg pubkey`). This lets the script run on machines
    without wireguard-tools, e.g. Windows where WireSock lives.
    """
    try:
        priv = subprocess.check_output(["wg", "genkey"]).decode().strip()
        pub = subprocess.check_output(["wg", "pubkey"], input=priv.encode()).decode().strip()
        return priv, pub
    except (OSError, subprocess.CalledProcessError):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        priv_raw = os.urandom(32)
        priv = base64.b64encode(priv_raw).decode()
        pub = base64.b64encode(
            X25519PrivateKey.from_private_bytes(priv_raw)
            .public_key().public_bytes_raw()).decode()
        return priv, pub


def fetch_wg_config(hostname, device_token, device_secret, pubkey, ca=None,
                    sni=True):
    ca = ca or CA_CERT or resolve_ca_cert()
    url = "https://%s.cg-dialup.net:1337/addKey?pubkey=%s" % (
        hostname.lower(), urllib.parse.quote(pubkey))
    _, r = http("GET", url, token=(device_token, device_secret), verify=ca,
                sni=sni)
    if r.get("status") != "OK":
        raise SystemExit("addKey failed: %s" % json.dumps(r))
    return r


def build_conf(priv, hostname, server_key, server_port, peer_ip, dns_servers):
    raw_dns = dns_servers if isinstance(dns_servers, list) else ([dns_servers] if dns_servers else [])
    dns = ", ".join(s.strip() for s in raw_dns if s and s.strip()) or "10.101.0.243"
    host = hostname.lower()
    if "." not in host:
        host += ".cg-dialup.net"  # API returns short names; Endpoint needs the FQDN
    ip = (peer_ip or "").strip()
    if "/" not in ip:
        ip += "/32"  # addKey returns a bare IPv4 address; Android/iOS require CIDR
    return (
        "[Interface]\n"
        "Address = %s\n"
        "DNS = %s\n"
        "PrivateKey = %s\n"
        "\n"
        "[Peer]\n"
        "PublicKey = %s\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "Endpoint = %s:%s\n"
        "PersistentKeepalive = 25\n"
    ) % (ip, dns, priv, server_key, host, server_port)


def main():
    ap = argparse.ArgumentParser(description="Fetch a CyberGhost WireGuard config")
    ap.add_argument("--user", default=os.environ.get("CYBERGHOST_USER"),
                    help="CyberGhost account e-mail (or set CYBERGHOST_USER)")
    ap.add_argument("--password", help="CyberGhost password (or set CYBERGHOST_PASS; prompted if neither)")
    ap.add_argument("--password-mode", default="mask", choices=["mask", "hidden", "show"],
                    help="how to echo the prompted password: mask=* per char (default), "
                         "hidden=nothing, show=plaintext")
    ap.add_argument("--server-type", default="traffic",
                    choices=["traffic", "streaming", "torrent"])
    ap.add_argument("--service", default=None,
                    help="streaming service to target, e.g. netflix (server-type=streaming)")
    ap.add_argument("--country", default="us")
    ap.add_argument("--city", default=None)
    ap.add_argument("--app-key", default=None,
                    help="API x-app-key value (or set X_APP_KEY; see extract/extract_x_app_key.py)")
    ap.add_argument("--app-key-bin", default=None,
                    help="path to YOUR copy of the official cyberghostvpn binary; "
                         "extracts the x-app-key in-process (or set X_APP_KEY_BIN)")
    ap.add_argument("--app-key-file", default=None,
                    help="read the x-app-key value from a file (or set X_APP_KEY_FILE)")
    ap.add_argument("--ca-cert", default=None,
                    help="TLS CA for the addKey endpoint (or set X_CA_CERT; "
                         "defaults to ./wireguard/ca.crt next to --app-key-bin)")
    ap.add_argument("--list-countries", action="store_true")
    ap.add_argument("--list-services", action="store_true")
    ap.add_argument("--list-servers", metavar="CC")
    ap.add_argument("--device-name", default=socket.gethostname())
    args = ap.parse_args()

    global APP_KEY, CA_CERT
    APP_KEY = resolve_app_key(args.app_key, args.app_key_file, args.app_key_bin)
    CA_CERT = resolve_ca_cert(args.ca_cert, args.app_key_bin)

    user = args.user or ask("CyberGhost account e-mail")
    password = args.password or os.environ.get("CYBERGHOST_PASS") or read_secret("CyberGhost password: ", mode=args.password_mode)

    bearer = login(user, password)
    ud = user_data(bearer)
    print("# logged in as %s (plan %s)" % (user, ud["plan_id"]), file=sys.stderr)

    st = args.server_type

    if args.list_services:
        for s in streaming_services(bearer, ud):
            print("%-20s  %-3s  content_id=%s" % (
                s.get("name"), s.get("countryCode"), s.get("content_id")))
        return

    if args.list_countries:
        if st == "torrent":
            rows = torrent_countries(bearer, ud)
            for c in rows:
                print("%-3s  %s servers" % (c.get("countrycode"), c.get("total_servers")))
        elif st == "streaming":
            rows = streaming_services(bearer, ud)
            for c in rows:
                print("%-20s  %-3s  content_id=%s" % (c.get("name"), c.get("countrycode"), c.get("content_id")))
        else:
            rows = traffic_countries(bearer, ud)
            for c in rows:
                print("%-3s  %s servers" % (c.get("countrycode"), c.get("total_servers")))
        return

    if args.list_servers:
        cc = args.list_servers
        if st == "torrent":
            data = group_instances(torrent_instances(bearer, ud, cc))
        elif st == "streaming":
            svc = resolve_streaming(bearer, ud, args.service or "")
            data = group_instances(streaming_instances(bearer, ud, svc["content_id"]))
        else:
            data = group_instances(traffic_instances(bearer, ud, cc))
        for city, insts in data.items():
            for k, v in insts.items():
                print("%-25s %-8s %s" % (city, k, v.get("real")))
        return

    # Resolve instances for the chosen server type
    if st == "torrent":
        data = group_instances(torrent_instances(bearer, ud, args.country))
    elif st == "streaming":
        svc = resolve_streaming(bearer, ud, args.service or "")
        print("# streaming service: %s (content_id=%s)" % (svc["name"], svc["content_id"]),
              file=sys.stderr)
        data = group_instances(streaming_instances(bearer, ud, svc["content_id"]))
    else:
        data = group_instances(traffic_instances(bearer, ud, args.country))

    hostname = pick_server(data, args.city)
    print("# selected server: %s.cg-dialup.net" % hostname, file=sys.stderr)

    dtok, dsec = get_or_create_device(bearer, args.device_name)
    print("# device token: %s" % dtok, file=sys.stderr)
    print("# device secret: %s" % dsec, file=sys.stderr)

    priv, pub = gen_keys()
    out = fetch_wg_config(hostname, dtok, dsec, pub)
    print(build_conf(priv, hostname,
                     out["server_key"], out["server_port"],
                     out["peer_ip"], out.get("dns_servers")))


def resolve_streaming(bearer, ud, service):
    services = streaming_services(bearer, ud)
    match = next((s for s in services
                  if (s.get("name") or "").lower() == service.lower()), None)
    if match is None:
        names = ", ".join(s.get("name") or "?" for s in services)
        raise SystemExit("Streaming service %r not found. Available: %s"
                         % (service, names))
    return match


def ask(prompt, default=None):
    """Prompt with an optional default; returns the input (stripped)."""
    suffix = (" [%s]" % default) if default else ""
    try:
        value = input(prompt + suffix + ": ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit("Aborted.")
    return value or (default or "")


def pick_choice(prompt, options):
    """Show numbered options and return the chosen item (its value)."""
    for i, (label, value) in enumerate(options, 1):
        print("  %2d) %s" % (i, label))
    while True:
        raw = ask(prompt)
        try:
            idx = int(raw)
            if 1 <= idx <= len(options):
                return options[idx - 1][1]
        except ValueError:
            pass
        if raw.lower() in ("q", "quit"):
            raise SystemExit("Aborted.")
        print("  Invalid choice, try again.")


def interactive():
    """Friendly wizard when the script is invoked with no arguments."""
    print("CyberGhost WireGuard helper (interactive)")
    print("-" * 46)

    # Credentials come from the environment when present (CYBERGHOST_USER /
    # CYBERGHOST_PASS, e.g. injected from a secret manager), otherwise prompt.
    # The x-app-key value is never stored here; bring it via X_APP_KEY or
    # X_APP_KEY_BIN (path to your official client binary), or paste it when
    # prompted. See extract/extract_x_app_key.py. The TLS CA is read from
    # X_CA_CERT or ./wireguard/ca.crt next to that binary.
    global APP_KEY, CA_CERT
    APP_KEY = resolve_app_key()
    CA_CERT = resolve_ca_cert()
    user = os.environ.get("CYBERGHOST_USER") or ask("CyberGhost account e-mail")
    password = os.environ.get("CYBERGHOST_PASS") or read_secret("CyberGhost password: ", mode="mask")
    bearer = login(user, password)
    ud = user_data(bearer)
    print("\nLogged in as %s (plan id %s)\n" % (user, ud["plan_id"]))

    # 1. server type
    server_type = pick_choice("Choose server type", [
        ("Traffic (default)", "traffic"),
        ("Streaming (e.g. Netflix)", "streaming"),
        ("Torrent (P2P)", "torrent"),
    ])

    # 2. streaming service (only for streaming)
    service = None
    if server_type == "streaming":
        svcs = streaming_services(bearer, ud)
        if not svcs:
            raise SystemExit("No streaming services available for your plan.")
        print("\nAvailable streaming services:")
        service = pick_choice("Choose a streaming service",
                              [("%s  (%s)  content_id=%s" % (s.get("name"),
                                                             s.get("countrycode"),
                                                             s.get("content_id")),
                                s) for s in svcs])

    # 3. action
    action = pick_choice("What do you want to do?", [
        ("Connect and print a WireGuard config (recommended)", "connect"),
        ("List countries / services", "list"),
        ("List servers for a country", "listservers"),
    ])

    if action == "list":
        if server_type == "streaming":
            for s in streaming_services(bearer, ud):
                print("  %-20s %-3s content_id=%s" % (s.get("name"),
                                                      s.get("countrycode"),
                                                      s.get("content_id")))
        elif server_type == "torrent":
            for c in torrent_countries(bearer, ud):
                print("  %-3s  %s servers" % (c.get("countrycode"), c.get("total_servers")))
        else:
            for c in traffic_countries(bearer, ud):
                print("  %-3s  %s servers" % (c.get("countrycode"), c.get("total_servers")))
        return

    if action == "listservers":
        cc = ask("Country code", "us")
        if server_type == "streaming":
            data = group_instances(streaming_instances(bearer, ud, service["content_id"]))
        elif server_type == "torrent":
            data = group_instances(torrent_instances(bearer, ud, cc))
        else:
            data = group_instances(traffic_instances(bearer, ud, cc))
        for city, insts in data.items():
            for k, v in insts.items():
                print("  %-25s %-8s %s" % (city, k, v.get("real")))
        return

    # ---- connect ----
    if server_type == "streaming":
        print("\nUsing streaming service: %s (content_id=%s)"
              % (service.get("name"), service.get("content_id")))
        data = group_instances(streaming_instances(bearer, ud, service["content_id"]))
    elif server_type == "torrent":
        cc = ask("Country code", "de")
        data = group_instances(torrent_instances(bearer, ud, cc))
    else:
        cc = ask("Country code", "us")
        data = group_instances(traffic_instances(bearer, ud, cc))

    cities = list(data.keys())
    if not cities:
        raise SystemExit("No servers returned for that selection.")
    print("\nCities available: %s" % ", ".join(cities))
    city = ask("City (Enter = random)", "")
    hostname = pick_server(data, city or None)
    print("\nSelected server: %s.cg-dialup.net" % hostname)

    dtok, dsec = get_or_create_device(bearer, socket.gethostname())
    print("Device token: %s" % dtok)
    print("Device secret: %s" % dsec)

    priv, pub = gen_keys()
    out = fetch_wg_config(hostname, dtok, dsec, pub)
    conf = build_conf(priv, hostname,
                      out["server_key"], out["server_port"],
                      out["peer_ip"], out.get("dns_servers"))

    print("\n" + "=" * 46)
    print("WireGuard config:")
    print("=" * 46)
    print(conf)

    save = ask("\nSave to file?", "n")
    if save.lower() in ("y", "yes"):
        path = ask("File path", "~/wireguard-cg.conf")
        path = os.path.expanduser(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(conf)
        print("Saved to %s" % path)


if __name__ == "__main__":
    try:
        if len(sys.argv) == 1:
            sys.exit(interactive())
        main()
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
