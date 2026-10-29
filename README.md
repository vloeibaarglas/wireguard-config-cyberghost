# WireGuard Config for CyberGhost

Generate WireGuard configs for a CyberGhost subscription, for use with any WireGuard client (`wg-quick`, WireSock, etc.). Talks to the same private API as the official Linux client.

## Requirements

- Python 3.8+
- `cryptography` (only for keygen when the `wg` CLI is absent)
- `wireguard-tools` (`wg`) — optional
- An `x-app-key` value, supplied at runtime (see Setup)

## Setup

1. Download the official Linux client from the official download page ([example](https://download.cyberghostvpn.com/linux/cyberghostvpn-debian-12-1.5.0.zip)) and unzip it. You need two files from it:
   - binary: `cyberghostvpn-debian-12-1.5.0/cyberghost/cyberghostvpn` (for the key)
   - CA: `cyberghostvpn-debian-12-1.5.0/cyberghost/wireguard/ca.crt` (or `--ca-cert`)
2. Extract the `x-app-key`:
   ```bash
   python3 extract/extract_x_app_key.py /path/to/cyberghostvpn
   ```
3. Pass it via `--app-key KEY`, `X_APP_KEY`, or `--app-key-file PATH` (prompted if omitted).

## Usage

```bash
# Wizard
python3 cyberghost_wireguard.py

# Print a config
python3 cyberghost_wireguard.py --user you@example.com --password 'pass' --country us

# Save and connect
python3 cyberghost_wireguard.py --user you@example.com --password 'pass' --country us > wg.conf
sudo wg-quick up wg
```

`--server-type traffic|streaming|torrent`, `--service`, `--city`, `--list-services`, `--list-countries`, `--list-servers CC`; `--help` lists all.

## How it works

Requests go to `https://v2-api.cyberghostvpn.com/v2` with the runtime `x-app-key`: login (JWT) → reuse/create device slot → pick server → `GET https://{server}.cg-dialup.net:1337/addKey?pubkey=<base64>` returns server key, port, IP, DNS. Keys are generated locally; only the public key leaves the machine.

## Rotation helper

[`rotate/`](rotate/) patches the rotating keys into an existing WireSock/WireGuard `.conf` (backup first). Written for Windows; Linux users can adapt it.

## License

MIT — see [LICENSE](LICENSE).
