#!/usr/bin/env python3
"""
extract_x_app_key.py — read the static `x-app-key` from the OFFICIAL
CyberGhost Linux client binary THAT YOU PROVIDE.

This repository never ships, embeds, or distributes any CyberGhost key in
any form — no literals in the source, no value in the README, no value in
this file. You obtain the official `cyberghostvpn` binary yourself, then
point this script at it and it prints the key that is *already present*
in that binary:

    python3 extract_x_app_key.py /path/to/cyberghostvpn
    # -> prints one line: the key found in your binary

Then feed the printed value to cyberghost_wireguard.py:

    python3 cyberghost_wireguard.py --user u --password p \\
        --app-key "$(python3 extract_x_app_key.py /path/to/cyberghostvpn)" ...

What this extracts
------------------
The Linux client is a PyInstaller onefile build. The key lives in the
`configs.api` module, which PyInstaller bundles as bytecode inside the
embedded PYZ archive. This script:

  1. finds the CArchive cookie (magic MEI\\x0c\\x0b\\x0a\\x0b\\x0e) at the end;
  2. reads the archive's table of contents (TOC) using PyInstaller's entry
     format (big-endian, entry-size-prefixed);
  3. locates PYZ.pyz, decompresses it, and walks its marshalled TOC to
     find `configs.api`;
  4. decompresses that module, unmarshals, and walks the code constants
     for the long base64ish string.

The cookie/TOC layouts below mirror the open-source pyinstxtractor-ng
reader (which documents PyInstaller's own CArchive/PYZ layout). Nothing
here is derived from CyberGhost's business logic — only the static key
value, which you supply by pointing this script at YOUR copy of the
official client.

No key value appears anywhere in this file or this repository.
"""
import re
import struct
import sys
import marshal
import zlib

MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
PYZ_MAGIC = b"PYZ\x00"

# PyInstaller CArchive cookies (big-endian, matching pyinstxtractor-ng):
#   2.1+: magic + length + toc offset + toc len + pyver + pylibname (88 B)
#   2.0 : magic + length + toc offset + toc len + pyver (24 B)
COOKIE_FMT_21 = "!8sIIii64s"
COOKIE_FMT_20 = "!8siiii"

# One CArchive TOC entry header (big-endian), then NUL-terminated name:
#   entrySize(i) + entryPos(I) + cmprsdSize(I) + uncmprsdSize(I)
#   + cmprsFlag(B) + typeCode(c) + name
TOC_HEADER_FMT = "!iIIIBc"
TOC_HEADER_SIZE = struct.calcsize(TOC_HEADER_FMT)  # 18


def find_cookie(data):
    """Return the offset of the CArchive magic (last occurrence)."""
    idx = data.rfind(MAGIC)
    if idx < 0:
        raise ValueError("no MEI cookie found; not a PyInstaller onefile?")
    return idx


def parse_cookie(data, idx):
    """Decode the cookie; returns dict with overlay/TOC geometry.

    Mirrors pyinstxtractor-ng: overlayPos = fileSize - (length + tail),
    where tail = bytes after the cookie (usually zero).
    """
    n = len(data)
    # Prefer the modern 2.1+ cookie; fall back to 2.0.
    for fmt in (COOKIE_FMT_21, COOKIE_FMT_20):
        size = struct.calcsize(fmt)
        if idx + size > n:
            continue
        try:
            fields = struct.unpack_from(fmt, data, idx)
        except struct.error:
            continue
        if fields[0] != MAGIC:
            continue
        length, tocoff, toclen = fields[1], fields[2], fields[3]
        pyver = fields[4]
        if not (0 < length <= n):
            continue
        if tocoff + toclen > length:
            continue
        tail = n - idx - size
        overlay_pos = n - (length + tail)
        if overlay_pos < 0:
            continue
        toc_pos = overlay_pos + tocoff
        if toc_pos < 0 or toc_pos + toclen > n:
            continue
        return {"length": length, "tocoff": tocoff, "toclen": toclen,
                "pyver": pyver, "overlay_pos": overlay_pos,
                "toc_pos": toc_pos, "cookie_size": size}
    raise ValueError("could not decode CArchive cookie")


def iter_toc(data, cookie):
    """Yield (name, pos, clen, uclen, cmprsFlag, typecode) per TOC entry."""
    pos = cookie["toc_pos"]
    end = pos + cookie["toclen"]
    n = len(data)
    base = cookie["overlay_pos"]
    while pos < end:
        if pos + 4 > n:
            break
        (entry_size,) = struct.unpack_from("!i", data, pos)
        if entry_size < TOC_HEADER_SIZE or pos + entry_size > end:
            raise ValueError("bad CArchive TOC entry size %r" % (entry_size,))
        (entry_pos, clen, uclen, flag, tcode) = struct.unpack_from(
            "!IIIBc", data, pos + 4)
        name_raw = data[pos + TOC_HEADER_SIZE: pos + entry_size]
        name = name_raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
        yield name, base + entry_pos, clen, uclen, flag, tcode
        pos += entry_size


def find_pyz(data, cookie):
    """Return the decompressed PYZ blob bytes."""
    for name, off, clen, uclen, flag, tcode in iter_toc(data, cookie):
        if name == "PYZ.pyz":
            raw = data[off: off + clen]
            blob = zlib.decompress(raw) if flag == 1 else raw
            if blob[:4] != PYZ_MAGIC:
                raise ValueError("PYZ entry did not decompress to PYZ magic")
            return blob
    raise ValueError("PYZ.pyz not found")


def read_module_from_pyz(pyz_blob, wanted_dotted="configs.api"):
    """Return decompressed marshalled-code bytes for a PYZ module."""
    if pyz_blob[:4] != PYZ_MAGIC:
        raise ValueError("bad PYZ magic")
    # PYZ header: magic(4) + pyc magic(4) + TOC offset BE(4).
    (toc_pos,) = struct.unpack_from("!i", pyz_blob, 8)
    toc = marshal.loads(pyz_blob[toc_pos:])
    if isinstance(toc, list):
        toc = dict(toc)
    for alias in (wanted_dotted, wanted_dotted.replace(".", "/")):
        if alias in toc:
            entry = toc[alias]
            break
    else:
        raise KeyError("%s not in PYZ" % wanted_dotted)
    ispkg, pos, length = entry
    raw = pyz_blob[pos: pos + length]
    return zlib.decompress(raw)


def walk_consts(co, out):
    if isinstance(co, str):
        out.add(co)
    elif isinstance(co, (tuple, list)):
        for x in co:
            walk_consts(x, out)
    elif hasattr(co, "co_consts"):
        for c in co.co_consts:
            walk_consts(c, out)


def pick_key(strings):
    cands = [s for s in strings
             if len(s) >= 32 and s.isascii() and s.isalnum()
             and any(c.isalpha() for c in s)]
    if not cands:
        raise RuntimeError("no x-app-key candidate found in configs.api")
    return max(cands, key=len)


def extract_key(path):
    data = open(path, "rb").read()
    cookie = parse_cookie(data, find_cookie(data))
    pyz = find_pyz(data, cookie)
    mod = read_module_from_pyz(pyz, "configs.api")
    # PYZ entries decompress straight to a marshalled code object
    # (pyinstxtractor re-adds the 16-byte pyc header only when writing
    # files to disk). Older blobs may already carry it — try both.
    code = None
    for off in (0, 16):
        try:
            obj = marshal.loads(mod[off:] if off else mod)
            if hasattr(obj, "co_consts"):
                code = obj
                break
        except Exception:
            continue
    if code is not None:
        out = set()
        walk_consts(code, out)
        try:
            return pick_key(out)
        except RuntimeError:
            pass
    # Fallback: the key is plaintext in the module bytes; scan raw.
    blobs = [mod]
    try:
        blobs.append(marshal.dumps(code) if code is not None else b"")
    except Exception:
        pass
    best = ""
    for b in blobs:
        if not b:
            continue
        for m in re.findall(rb"[A-Za-z0-9]{32,}", b):
            s = m.decode("ascii")
            if any(c.isalpha() for c in s) and len(s) > len(best):
                best = s
    if best:
        return best
    raise RuntimeError("no x-app-key candidate found in configs.api")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python3 extract_x_app_key.py /path/to/cyberghostvpn")
    print(extract_key(sys.argv[1]))
