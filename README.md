# SmartShield IPS

**Behavioral, machine-learning-based Intrusion Prevention System for OT/ICS (factory) environments.**

SmartShield is a graduation project that adapts a behavioral network IPS for the
industrial world. It sits passively at the IT/OT boundary, watches a mirror of all
traffic, detects attacks against industrial protocols (Modbus, S7Comm, DNP3,
PROFINET, CIP, NTP/PTP), and can block attackers via `iptables` — with an **OT-safe**
guarantee that PLCs, HMIs, and SCADA servers are *never* auto-blocked.

---

## Table of Contents

- [What it does](#what-it-does)
- [Architecture](#architecture)
- [What we added ](#what-we-added)
- [OT/ICS attacks detected](#otics-attacks-detected)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Web interface](#web-interface)
- [Repository layout](#repository-layout)
- [Status & limitations](#status--limitations)
- [Team](#team)
- [License](#license)

---

## What it does

SmartShield receives a copy of network traffic (from a PCAP file or a live SPAN/TAP
port), parses it with **Zeek**, profiles every host, and runs a set of detection
modules over the resulting flows. When enough evidence accumulates against a source,
it raises an **alert**, optionally **blocks** the attacker, and can **export** the
alert to a SIEM.

The contribution of this project is the **OT Detection module**, which understands
industrial-protocol traffic and the specific ways OT devices are attacked — and an
**OT-safe blocking** layer that makes an IPS safe to run on a production line.

Key properties:

- **Passive** — monitors a traffic mirror; OT devices never see the sensor.
- **Behavioral** — flags abnormal *behavior* (floods, scans, unauthorized access),
  not just signatures.
- **OT-safe** — protected PLC/HMI/SCADA IPs are never passed to `iptables`.
- **Production-oriented** — Redis persistence, web authentication, systemd service,
  and Syslog/webhook export to a SIEM.

## Architecture

```
                 ┌──────────────────────────────────────────────────────┐
  SPAN / TAP  →  │  Zeek  →  Profiler  →  Redis pub/sub  →  Detection     │
  or PCAP file   │  (conn.log, modbus.log, …)        modules (incl. OT)   │
                 │                                        │               │
                 │   Evidence  →  threshold  →  Alert  →  ┤               │
                 │                                        ├─ Blocking (OT-safe)
                 │                                        ├─ Export (Slack/STIX/Syslog/Webhook)
                 │                                        └─ Web UI + Kalipso TUI
                 └──────────────────────────────────────────────────────┘
```

A full Semester-1 + Semester-2 architecture diagram is included:
[`SmartShield_Architecture.svg`](SmartShield_Architecture.svg).

Pipeline in words: **Zeek** parses packets into structured logs → the **profiler**
publishes each flow on Redis channels → **detection modules** subscribe and produce
**Evidence** → the **evidence/alert pipeline** raises an alert when the accumulated
threat crosses the threshold → **blocking**, **export**, and the **web interface**
act on it.

## What we added

| Area | Contribution | Where |
|---|---|---|
| OT detection | `ot_detection` module — flood, scan, and unauthorized-access detection across 6 OT protocols | `modules/ot_detection/` |
| OT Zeek scripts | OT protocol hooks and notices | `zeek-scripts/ot_protocols.zeek` |
| OT-safe blocking | PLC/HMI/SCADA IPs are never blocked | `modules/blocking/`, `config/ot_protected_devices.conf` |
| SIEM export | Syslog (RFC-5424) + HTTP webhook | `modules/exporting_alerts/syslog_exporter.py` |
| Web auth | Flask login, sessions | `webinterface/auth.py` |
| Persistence | Redis AOF/RDB so state survives reboots | `config/redis.conf` |
| Factory deploy | Bare-metal installer, systemd unit, production compose | `install/`, `docker/docker-compose.factory.yml` |

Everything else — the profiler, evidence/alert pipeline, Redis/SQLite storage, web
interface, Kalipso TUI, and the IT-side detection modules (Threat Intelligence,
PortScan, RNN C&C, Flow Alerts, ARP, HTTP Analyzer, and others) — made semester 1

## OT/ICS attacks detected

The OT module covers six protocols. Flood/volume detection works from `conn.log`
(`new_flow`) and is validated against real captures; per-message semantic detections
are implemented but depend on the Zeek OT parser (see [Status](#status--limitations)).

| Protocol | Port | Example detections |
|---|---|---|
| Modbus/TCP | 502 | connection/request flood, unauthorized master, write-coils, illegal function |
| S7Comm | 102 | job flood, unauthorized read/write, PLC STOP |
| DNP3 | 20000 | request flood, unauthorized function code |
| PROFINET DCP | 34964 | discovery flood |
| EtherNet/IP CIP | 44818 | explicit-message flood |
| NTP / PTP | 123 / 319 | time-sync spoofing |

Plus process/state attacks via Zeek notices: PLC mode-switch, watchdog manipulation,
valve cycling, motor cycling.

## Quick start

### Requirements

- Linux (Ubuntu 22.04 / 24.04 recommended), or Docker
- Zeek 8, Python 3.10+, Redis 7
- Root access for live capture and `iptables` blocking

### Analyze a PCAP file

```bash
python3 smartshield.py -f dataset/<capture>.pcap -o output/<run-name>
```

Results appear under `output/<run-name>/` (`alerts.json`, `alerts.log`, Zeek logs).

### Live capture (factory deployment)

```bash
sudo python3 smartshield.py -i eth1 -o output/live
```

`eth1` should be connected to a SPAN port or TAP and does **not** need an IP address.

### Docker

```bash
docker build -f docker/Dockerfile -t smartshield_gp:latest .
docker compose -f docker/docker-compose.factory.yml up -d
```

### Bare-metal factory install

```bash
sudo ./install/install_factory.sh
```

Installs Zeek, Python, Redis, the systemd service, and prompts for the monitoring
interface and web credentials.

## Configuration

Main config: [`config/smartshield.yaml`](config/smartshield.yaml). Factory-relevant
keys:

```yaml
parameters:
  analysis_direction: all          # detect inbound attacks TO OT devices
detection:
  evidence_detection_threshold: 0.15
ot_detection:
  modbus_flood_threshold: 20       # connections / 60 s
  dnp3_flood_threshold: 100        # requests / 60 s
  flood_window_seconds: 60
  connection_min_flood_packets: 200  # single-connection flood: packet floor
  packet_rate_threshold: 50          # single-connection flood: pkts/s floor
```

- **Protected OT devices** (never blocked): `config/ot_protected_devices.conf`
- **Authorized Modbus masters**: `config/modbus_authorized_masters.conf`

Leaving these files empty is safe: OT-safe blocking stays active (but protects no IPs),
and unauthorized-access detection is simply disabled. **Populate them before enabling
blocking in production.**

## Web interface

```
http://<server-ip>:55000
```

Credentials come from environment variables (`SMARTSHIELD_WEB_USER` /
`SMARTSHIELD_WEB_PASSWORD`); if unset, a default is used and the login page shows a
warning banner. Set them via `docker/.env` (Docker) or `/etc/smartshield/environment`
(bare-metal). Restrict port 55000 to your management VLAN — never expose it to the
internet.

## Repository layout

```
smartshield.py                 Entry point
smartshield_files/             Core engine (profiler, database, evidence/alert pipeline)
modules/                       Detection modules
  └─ ot_detection/             ★ OT/ICS detection module
zeek-scripts/                  Zeek parsing scripts (incl. ot_protocols.zeek)
config/                        YAML config + OT device / Modbus-master lists
webinterface/                  Flask web UI (incl. auth.py)
docker/                        Dockerfiles + factory compose
install/                       Bare-metal installer + systemd unit
dataset/                       Sample PCAPs
LICENSES/ · NOTICE · CITATION.cff   License & attribution
```

## Status & limitations

This is a graduation project — honest about what works:

- **Working:** flood/scan detection on OT ports (validated against real Modbus and
  DNP3 captures), OT-safe blocking, web auth, Redis persistence, Syslog/webhook export.
- **Partial:** deep per-message detections (Modbus write-coils, illegal function,
  S7 STOP, PLC mode-switch, watchdog/valve/motor) are implemented in the module but
  require the Zeek OT parser (`zeek-scripts/ot_protocols.zeek`) to publish per-PDU
  events on the `new_modbus` / `new_s7comm` / `new_dnp3` channels. Wiring that
  publisher is the main remaining task.
- **Out of scope:** application/infrastructure DoS such as OPC-UA memory exhaustion,
  historian/HMI/alarm floods, and switch MAC/STP attacks.

## Team

Mostafa Hamada · Zeyad Magdy · Ahmed Ashraf · Karim Walid
Supervisor: Dr. Islam El-Maddah

## License

GNU General Public License v2.0 — see [`LICENSES/`](LICENSES). 
