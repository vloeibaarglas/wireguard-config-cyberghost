@echo off
rem Rotate a local WireGuard/WireSock .conf via the CyberGhost API.
rem Requires Python 3.8+ with `cryptography` on PATH. Pass extra flags through:
rem   run-rotate.bat --country de
python "%~dp0rotate_wiresock.py" --conf "%USERPROFILE%\cg.conf" --ca-cert "%~dp0ca.crt" %*
