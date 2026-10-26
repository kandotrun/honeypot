#!/usr/bin/env python3
"""Patch the stock OpenCanary config at image build time.

Enables the approved sensor set, points logging at a rotating JSON
file, and leaves every other module disabled. Prints the effective
service keys so the build log shows exactly what was applied.
"""
import json
import sys

path = sys.argv[1]
with open(path) as f:
    cfg = json.load(f)

cfg["device.node_id"] = "opencanary-sakura"

# Services to run: name -> port. Everything else stays disabled.
services = {
    "ftp": 21,
    "http": 80,
    "https": 443,
    "httpproxy": 8080,
    "mysql": 3306,
    "mssql": 1433,
    "redis": 6379,
    "vnc": 5900,
    "sip": 5060,
}
for name, port in services.items():
    cfg[f"{name}.enabled"] = True
    cfg[f"{name}.port"] = port
for name in ("ssh", "telnet", "snmp", "ntp", "tftp", "git", "rdp", "smb"):
    if f"{name}.enabled" in cfg:
        cfg[f"{name}.enabled"] = False
cfg["portscan.enabled"] = False

# Logging: the stock file handler is dictConfig-style (filename and
# friends live at the handler's top level). Swap in the rotating
# handler in that same shape; a nested "kwargs" dict would collide
# with the top-level filename and break logger setup.
logger = cfg.get("logger", {})
handlers = logger.get("kwargs", {}).get("handlers", {})
file_handler = handlers.get("file")
if file_handler is not None:
    file_handler.pop("kwargs", None)
    file_handler["class"] = "logging.handlers.RotatingFileHandler"
    file_handler["filename"] = "/var/log/opencanary/opencanary.log"
    file_handler["maxBytes"] = 10485760
    file_handler["backupCount"] = 5

# HTTPS decoy uses the self-signed cert generated at image build.
cfg["https.certificate"] = "/etc/opencanaryd/cert.pem"
cfg["https.key"] = "/etc/opencanaryd/privkey.pem"

with open(path, "w") as f:
    json.dump(cfg, f, indent=4)

print("patched services:")
for key in sorted(cfg):
    if key.endswith(".enabled") or key.endswith(".port"):
        print(" ", key, "=", cfg[key])
