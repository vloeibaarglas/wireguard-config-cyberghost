#!/usr/bin/env python3
"""Rotate a local WireSock/WireGuard .conf straight from CyberGhost.

No server, no Cloudflare, no key extraction: you bake your static x-app-key
into this file (or X_APP_KEY env) once, then run daily. Flow mirrors the
official client: login (JWT) -> reuse device slot -> pick server ->
register fresh WireGuard pubkey (addKey) -> merge rotating keys into your
.conf, preserving your own settings (MTU, split-tunnel, #@ws: lines, ...).

Windows (PowerShell, needs `cryptography`: pip install cryptography):
    set X_APP_KEY=paste-your-key
    set CYBERGHOST_USER=you@example.com
    set CYBERGHOST_PASS=...
    python rotate_wiresock.py --conf "%USERPROFILE%\cg.conf"

Linux/macOS:
    X_APP_KEY=... CYBERGHOST_USER=... CYBERGHOST_PASS=... \
        python3 rotate_wiresock.py --conf ~/cg.conf

Only these keys rotate; everything else in your file is preserved:
  [Interface] Address, PrivateKey, DNS
  [Peer]      PublicKey, AllowedIPs, Endpoint, PersistentKeepalive
The #@ws: extensions below are enforced (params override the defaults).
Old file is backed up to <conf>.bak.YYYYMMDD-HHMMSS first.

You also need the client's ca.crt (TLS for the key-exchange endpoint) next to
the script or via --ca-cert. Copy it from the official Linux client zip:
    cyberghostvpn-debian-12-1.5.0/cyberghost/wireguard/ca.crt
"""
import argparse
import base64
import getpass
import os
import re
import shutil
import ssl
import sys
import tempfile
import time
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))  # repo root: cyberghost_wireguard.py
import cyberghost_wireguard as cg  # noqa: E402  (API + keypair + conf builder)

# ---------------------------------------------------------------------------
# Bake your static x-app-key here (or leave "" and use X_APP_KEY env / --app-key).
# Print it on the Linux host with:
#   python3 extract/extract_x_app_key.py \\
#       cyberghostvpn-debian-12-1.5.0/cyberghost/cyberghostvpn
# ---------------------------------------------------------------------------
APP_KEY = ""

MANAGED = {
    "Interface": ("Address", "PrivateKey", "DNS"),
    "Peer": ("PublicKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"),
}
HDR = re.compile(r"^\[(.+)\]$")
KV = re.compile(r"^([^#;][^=]*?)\s*=\s*(.*)$")


def parse_sections(lines):
    """Yield (kind, section, key, line) per line; kind in header/kv/other."""
    section = ""
    for line in lines:
        t = line.strip()
        m = HDR.match(t)
        if m:
            section = m.group(1)
            yield ("header", section, "", line)
            continue
        m = KV.match(t)
        if m and section:
            yield ("kv", section, m.group(1).strip(), line)
        else:
            yield ("other", section, "", line)


def fresh_values(conf_text):
    """Managed section -> key -> value from a freshly generated conf."""
    out, section = {}, ""
    for kind, section, key, line in parse_sections(conf_text.splitlines()):
        if kind == "kv" and key in MANAGED.get(section, ()):
            out.setdefault(section, {})[key] = line.split("=", 1)[1].strip()
    return out


def merge(existing_text, fresh):
    """Replace managed keys, keep everything else; append missing managed keys."""
    out, seen, section = [], set(), ""
    for kind, sec, key, line in parse_sections(existing_text.splitlines()):
        section = sec
        if (kind == "kv" and key in MANAGED.get(sec, ())
                and sec in fresh and key in fresh[sec]):
            out.append("%s = %s" % (key, fresh[sec][key]))
            seen.add(sec + "/" + key)
        else:
            out.append(line)
    for sec, keys in fresh.items():
        for key, val in keys.items():
            if sec + "/" + key in seen:
                continue
            for i, line in enumerate(out):
                if line.strip() == "[%s]" % sec:
                    out.insert(i + 1, "%s = %s" % (key, val))
                    break
            else:
                out += ["[%s]" % sec, "%s = %s" % (key, val)]
    return out


def ensure_line(lines, section, prefix, full):
    """Make sure `full` exists under [section]; never touch a tuned variant."""
    cur = ""
    for line in lines:
        t = line.strip()
        m = HDR.match(t)
        if m:
            cur = m.group(1)
            continue
        if cur == section and (t == full or t.lower().startswith(prefix.lower())):
            return lines
    for i, line in enumerate(lines):
        if line.strip() == "[%s]" % section:
            lines.insert(i + 1, full)
            return lines
    return lines + ["[%s]" % section, full]
def atomic_write(path, lines):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".",
                               prefix=".cg-rotate-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write("\r\n".join(lines) + "\r\n")
        shutil.move(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def bounce_wiresock():
    """Restart the WireSock service when present; harmless no-op otherwise."""
    if os.name != "nt":
        return "skipped (not Windows)"
    for svc in ("wiresock-client-service", "wiresock-pro-client-service"):
        try:
            cur = subprocess.run(["sc", "query", svc], capture_output=True,
                                 text=True, timeout=15).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        if "RUNNING" not in cur and "STOPPED" not in cur:
            continue
        try:
            subprocess.run(["sc", "stop", svc], check=True, capture_output=True,
                           timeout=30)
            for _ in range(20):
                time.sleep(1)
                q = subprocess.run(["sc", "query", svc], capture_output=True,
                                   text=True, timeout=15).stdout
                if "STOPPED" in q:
                    break
            subprocess.run(["sc", "start", svc], check=True, capture_output=True,
                           timeout=30)
            return "service %s restarted" % svc
        except (OSError, subprocess.SubprocessError, subprocess.CalledProcessError) as e:
            return "service %s present but restart failed (%s); reconnect in WireSock" % (svc, e)
    return "WireSock service not found; reconnect the profile in the GUI"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Rotate local WireSock conf from CyberGhost")
    ap.add_argument("--conf", required=True, help="local .conf to patch")
    ap.add_argument("--server-type", default="torrent",
                    choices=["traffic", "streaming", "torrent"])
    ap.add_argument("--service", default="", help="streaming service (exact name)")
    ap.add_argument("--country", default="mx")
    ap.add_argument("--city", default="")
    ap.add_argument("--user", default=os.environ.get("CYBERGHOST_USER"))
    ap.add_argument("--password", default=os.environ.get("CYBERGHOST_PASS"))
    ap.add_argument("--app-key", default=(os.environ.get("X_APP_KEY") or APP_KEY))
    ap.add_argument("--ca-cert", default=os.environ.get("X_CA_CERT"),
                    help="TLS CA for addKey (copy ca.crt from the client zip)")
    ap.add_argument("--device-name", default=os.environ.get("CYBERGHOST_DEVICE", "cg-site"))
    ap.add_argument("--vam", default="true", help="#@ws:VirtualAdapterMode value")
    ap.add_argument("--allowed-apps", default="",
                    help="empty string skips the line")
    ap.add_argument("--disallowed-apps", default="",
                    help="empty string skips the line")
    args = ap.parse_args(argv)

    def _path(p):
        return os.path.abspath(os.path.expanduser(os.path.expandvars(p or "")))
    args.conf = _path(args.conf)
    if args.ca_cert:
        args.ca_cert = _path(args.ca_cert)

    # Direct connection: API calls must not go through a proxy (urllib honors
    # proxy env vars) or a stale VPN tunnel — :1337 breaks under both.
    for _v in ("http_proxy", "https_proxy", "all_proxy",
               "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        os.environ.pop(_v, None)

    if not args.app_key:
        ap.error("x-app-key missing: bake APP_KEY in, or set X_APP_KEY / --app-key")
    user = args.user or input("CyberGhost account e-mail: ").strip()
    password = args.password or getpass.getpass("CyberGhost password: ")

    cg.APP_KEY = args.app_key
    bearer = cg.login(user, password)
    ud = cg.user_data(bearer)
    st = args.server_type
    if st == "torrent":
        data = cg.group_instances(cg.torrent_instances(bearer, ud, args.country))
    elif st == "streaming":
        if not args.service:
            ap.error("streaming needs --service")
        svc = cg.resolve_streaming(bearer, ud, args.service)
        data = cg.group_instances(cg.streaming_instances(bearer, ud, svc["content_id"]))
    else:
        data = cg.group_instances(cg.traffic_instances(bearer, ud, args.country))
    hostname = cg.pick_server(data, args.city or None)
    dtok, dsec = cg.get_or_create_device(bearer, args.device_name)
    priv, pub = cg.gen_keys()
    ca = None
    if args.ca_cert or os.environ.get("CG_APP_KEY_BIN"):
        ca = cg.resolve_ca_cert(args.ca_cert,
                                os.environ.get("CG_APP_KEY_BIN", ""))
    if ca is None:
        ap.error("--ca-cert missing: copy ca.crt from the client zip")
    try:
        out = cg.fetch_wg_config(hostname, dtok, dsec, pub, ca=ca)
    except (ssl.SSLError, urllib.error.URLError) as e:
        reason = (e if isinstance(e, ssl.SSLError)
                  else getattr(e, "reason", None))
        if not isinstance(reason, ssl.SSLError):
            raise
        print("SNI handshake blocked; retrying without SNI...")
        out = cg.fetch_wg_config(hostname, dtok, dsec, pub, ca=ca, sni=False)
    conf = cg.build_conf(priv, hostname, out["server_key"], out["server_port"],
                         out["peer_ip"], out.get("dns_servers"))
    print("server: %s" % hostname)

    lines = merge(open(args.conf, encoding="utf-8").read()
                  if os.path.exists(args.conf) else "[Interface]\n[Peer]\n",
                  fresh_values(conf))
    lines = ensure_line(lines, "Interface", "#@ws:VirtualAdapterMode",
                        "#@ws:VirtualAdapterMode = " + args.vam.lower())
    if args.allowed_apps:
        lines = ensure_line(lines, "Peer", "#@ws:AllowedApps",
                            "#@ws:AllowedApps = " + args.allowed_apps)
    if args.disallowed_apps:
        lines = ensure_line(lines, "Peer", "#@ws:DisallowedApps",
                            "#@ws:DisallowedApps = " + args.disallowed_apps)
    if not any(l.strip().startswith("PrivateKey") for l in lines):
        sys.exit("refusing to write: no PrivateKey merged (bad API response?)")

    if os.path.exists(args.conf):
        bak = "%s.bak.%s" % (args.conf, time.strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(args.conf, bak)
        print("backup: %s" % bak)
    atomic_write(args.conf, lines)
    print("wrote %s" % args.conf)
    print(bounce_wiresock())


if __name__ == "__main__":
    main()
