# Windows rotation: CyberGhost → WireSock

`rotate_wiresock.py` refreshes the rotating keys in a local `.conf` straight from CyberGhost's API (login → reuse device slot → register fresh key → merge, backup first). Nothing to host.

## Files

Put these in one folder (e.g. `C:\WireGuard\`): `rotate_wiresock.py` (this folder), `cyberghost_wireguard.py` (repo root), `ca.crt` (official Linux client zip), `run-rotate.bat` (optional launcher). Needs Python 3.8+ with `cryptography`.

## Secrets (once)

Print the static app key on the Linux host:

```bash
python3 extract/extract_x_app_key.py cyberghostvpn-debian-12-1.5.0/cyberghost/cyberghostvpn
```

Then set env vars (User level; System level if the scheduled task runs as SYSTEM):

```powershell
[Environment]::SetEnvironmentVariable('X_APP_KEY', '<key>', 'User')
[Environment]::SetEnvironmentVariable('CYBERGHOST_USER', 'you@example.com', 'User')
[Environment]::SetEnvironmentVariable('CYBERGHOST_PASS', '...', 'User')
```

## Run

```powershell
python C:\WireGuard\rotate_wiresock.py --conf "$env:USERPROFILE\cg.conf" --ca-cert C:\WireGuard\ca.crt
```

or `run-rotate.bat`. Schedule daily via Task Scheduler (highest privileges); the script bounces the WireSock service, or re-import the file into the GUI profile.

Flags: `--server-type traffic|streaming|torrent`, `--country`, `--city`, `--service`, `--device-name`, `--vam`, `--allowed-apps`, `--disallowed-apps`, `--app-key`, `--ca-cert`, `--conf`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `x-app-key` / `--ca-cert` missing | env var, baked value, or flag not visible in this shell |
| `Login failed` | wrong `CYBERGHOST_USER`/`PASS` |
| `SSL: WRONG_VERSION_NUMBER` on `:1337` | disconnect the VPN first, then rotate |
