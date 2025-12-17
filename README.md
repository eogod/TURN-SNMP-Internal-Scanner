# TURN-SNMP Internal Scanner

A Python tool that abuses a **misconfigured TURN server** (with known credentials or open allocation) to **proxy UDP traffic** into an internal network and perform **SNMP queries** (e.g., on port 161). It scans a defined IP range (e.g., `192.168.xx.0/24`) and extracts SNMP responses—useful for discovering internal devices or hunting for secrets like flags.

> ⚠️ **For authorized security testing only.** Unauthorized use may violate laws or terms of service.

## How It Works
1. Authenticates to the TURN server over **TCP**.
2. Requests a UDP relay allocation.
3. For each target IP:
   - Creates a permission to the internal IP:161.
   - Sends a crafted SNMP GET request via TURN **Send Indication**.
   - Listens for a **Data Indication** containing the SNMP response.
4. Parses and displays responses; optionally extracts patterns (e.g., `flag{...}`).

## Setup
Edit the top of the script to configure:
- `TURN_IP`, `TURN_PORT`
- `USERNAME`, `PASSWORD` (if auth is required)
- `NET_PREFIX` (e.g., `"192.168.1."`)
- Optional: update `SNMP_GET_SYSDESCR` bytes for different OIDs

## Requirements
```bash
pip install
# (no external deps — uses only standard library)
```
## Run
```bash
python3 poc.py
```
