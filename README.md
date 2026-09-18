# Drone Forensic Toolkit (DFT)
**Indigenous, Modular Digital Forensic Framework for UAV Investigations**  
*Developed for the IIT Bombay Techfest Grand Challenge: Objective 1*

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Forensic Standard](https://img.shields.io/badge/ISO%2FIEC-27037%3A2012-green.svg)](https://www.iso.org/standard/44381.html)
[![Forensic Standard](https://img.shields.io/badge/ISO%2FIEC-27042%3A2015-green.svg)](https://www.iso.org/standard/44385.html)
[![Statutory Grounding](https://img.shields.io/badge/DGCA-Drone%20Rules%202021-orange.svg)](https://digitalsky.dgca.gov.in/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Vector Store](https://img.shields.io/badge/ChromaDB-Vector%20Store-purple.svg)](https://www.trychroma.com/)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](LICENSE)

---

## Table of Contents
- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Core Capabilities](#core-capabilities)
  - [1. 5-Layer Forensic Architecture](#1-5-layer-forensic-architecture)
  - [2. Forensic RAG Subsystem (AI Forensic Analyst)](#2-forensic-rag-subsystem-ai-forensic-analyst)
  - [3. Multi-Source Evidence & Platform Support](#3-multi-source-evidence--platform-support)
    - [Extending Support for Custom Drone Formats (`dft/plugins/base.py`)](#extending-support-for-custom-drone-formats-dftpluginsbasepy)
  - [4. Ground Control Station (GCS) Audit](#4-ground-control-station-gcs-audit)
  - [5. Mobile Companion App Forensics](#5-mobile-companion-app-forensics)
  - [6. Forensic Wireless Acquisition](#6-forensic-wireless-acquisition)
  - [7. Aerial Media & Video Telemetry Extractor](#7-aerial-media--video-telemetry-extractor)
  - [8. Geofencing & Airspace Regulatory Engine](#8-geofencing--airspace-regulatory-engine)
- [Quickstart & Installation](#quickstart--installation)
- [Interactive Web Dashboard](#interactive-web-dashboard)
- [Complete CLI Reference](#complete-cli-reference)
- [REST API Reference](#rest-api-reference)
- [Reference Forensic Benchmark Suites](#reference-forensic-benchmark-suites)
- [Directory Structure](#directory-structure)
- [Legal Admissibility & Forensic Soundness](#legal-admissibility--forensic-soundness)

---

## Overview

The **Drone Forensic Toolkit (DFT)** is an indigenous, end-to-end digital forensic solution designed to acquire, preserve, reconstruct, analyze, and report digital evidence from Unmanned Aerial Vehicles (UAVs) in a legally defensible and court-admissible manner.

Addressing the critical challenge of hardware fragmentation, proprietary flight formats, volatile telemetry, and unstandardized acquisition workflows, DFT offers a unified platform covering:
- **Onboard Flight Controllers & Blackboxes** (DJI, ArduPilot, PX4, Parrot, Betaflight/iNav).
- **Ground Control Stations (GCS)** (QGroundControl, Mission Planner, DJI Assistant, Autel Explorer).
- **Companion Mobile Applications** (DJI Fly, DJI Go 4, Autel Explorer, FreeFlight, QGC Mobile).
- **Over-the-Air Wireless Transmissions** (Wi-Fi AP FTP, MAVLink UDP streams, wireless ADB).
- **Aerial Media & Video Telemetry** (EXIF GPS IFD tags, rational degrees, MP4/MOV embedded `.srt` subtitles).
- **Forensic RAG (Retrieval-Augmented Generation)**: Grounded natural-language query engine powered by ChromaDB, Groq LLaMA-3.3, and local Ollama for air-gapped forensic laboratories.

DFT complies with **ISO/IEC 27037:2012** (*Guidelines for identification, collection, acquisition, and preservation of digital evidence*) and **ISO/IEC 27042:2015** (*Guidelines for analysis and interpretation of digital evidence*), satisfying requirements under the Indian Evidence Act / Bharatiya Sakshya Adhiniyam (BSA) for electronic records.

DFT is deployed and accessible at https://drone-sec-x89f.onrender.com/

---

## System Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 DRONE FORENSIC TOOLKIT (DFT)                           │
└────────────────────────────────────────────────────────────────────────────────────────┘
                                           │
 ┌─────────────────────────────────────────┴────────────────────────────────────────────┐
 │  LAYER 1: ACQUISITION                                                                │
 │  • Physical Disk Imaging (.dd, raw bit-stream) • Expert Witness Format (E01)         │
 │  • Logical Evidence Extraction                 • File Carver (Deleted log carving)   │
 │  • Software Write-Block Canary Verification    • Over-The-Air Wireless Acquisition   │
 └─────────────────────────────────────────┬────────────────────────────────────────────┘
                                           │
 ┌─────────────────────────────────────────┴────────────────────────────────────────────┐
 │  LAYER 2: PRESERVATION & CHAIN OF CUSTODY                                            │
 │  • Dual Cryptographic Hashing: SHA-256 + SHA-3-256 (+ MD5 legacy cross-check)        │
 │  • Tamper-Evident Append-Only Chain of Custody (HMAC-SHA256 Cryptographic Chaining) │
 │  • Isolated Case Repositories in Forensic Evidence Vault                             │
 └─────────────────────────────────────────┬────────────────────────────────────────────┘
                                           │
 ┌─────────────────────────────────────────┴────────────────────────────────────────────┐
 │  LAYER 3: VENDOR-NEUTRAL PARSING ENGINE                                              │
 │  • Flight Controllers : DJI (.DAT, .txt, .srt) | ArduPilot (.bin, .log, .tlog)       │
 │                         PX4 (.ulg, .csv)       | Parrot (.pud, .json)                │
 │                         Betaflight/iNav (.bbl, .txt)                                 │
 │  • GCS Software       : QGroundControl (.plan) | Mission Planner (.param, .waypoints)│
 │  • Mobile Apps        : DJI Fly/Go 4, Autel Explorer, FreeFlight, QGC Mobile         │
 │  • Aerial Media       : EXIF GPS IFD tags      | Video Subtitle Telemetry (.srt)     │
 └─────────────────────────────────────────┬────────────────────────────────────────────┘
                                           │
 ┌─────────────────────────────────────────┴────────────────────────────────────────────┐
 │  LAYER 4: FORENSIC ANALYSIS & RECONSTRUCTION                                         │
 │  • Unified UTC Chronological Timeline Engine                                         │
 │  • 2D/3D Trajectory Reconstruction (GeoJSON & Google Earth KML with 3D Extrusion)    │
 │  • Geofence Breach Engine (DGCA Drone Rules 2021 Red/Yellow Zones & Custom Polygons) │
 │  • Anti-Forensics & Anomaly Detection (GPS Spoofing, Clock Drift, Sudden Power Loss) │
 │  • Mission Adherence Auditor (Planned Waypoint Route vs. Flown Trajectory)           │
 └─────────────────────────────────────────┬────────────────────────────────────────────┘
                                           │
 ┌─────────────────────────────────────────┴────────────────────────────────────────────┐
 │  LAYER 5: AI FORENSIC RAG & STANDARDIZED REPORTING                                   │
 │  • Forensic RAG AI Analyst : ChromaDB Vector Collections + Groq LLaMA-3.3-70B        │
 │                              Fallback: Local Ollama (Air-Gapped) & Extractive Engine  │
 │                              Statutory Grounding: DGCA 2021, FAA Part 107, ISO 27037 │
 │  • Court-Admissible Reports: Standalone Self-Contained HTML (Leaflet Map & Charts)   │
 │                              Machine-Readable JSON | Digital Forensics XML (DFXML)   │
 └──────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Core Capabilities

### 1. 5-Layer Forensic Architecture

1. **Acquisition Engine**:
   - Bit-stream physical disk imaging (`.dd`) and Expert Witness Format (`.E01`) with metadata headers.
   - Deep file carver for recovering deleted or corrupted flight logs (`.bin`, `.ulg`, `.pud`, `.DAT`) based on file signatures and magic bytes.
   - Software-only write-blocking verification using canary test probes to guarantee zero target tampering before extraction.
2. **Preservation & Chain of Custody**:
   - Dual cryptographic hashing (**SHA-256 + NIST SHA-3-256**) generated instantly upon acquisition.
   - Append-only, tamper-evident audit ledger (`audit_trail.jsonl`) cryptographically linked using **HMAC-SHA256**.
   - Case isolation within secure evidence vaults (`forensic_cases_vault/<case_id>/`).
3. **Parsing Engine**:
   - Decodes multi-modal flight logs, proprietary binary structures, JSON telemetry, MAVLink packets, and sensor feeds.
4. **Analysis & Reconstruction**:
   - Harmonizes multi-source timestamps into a synchronized UTC forensic timeline.
   - Detects anti-forensic artifacts: GPS time travel, coordinate spoofing, sensor dropouts, abrupt battery disconnects, and packet injection.
   - Evaluates planned waypoint missions against actual flight paths to compute route compliance and identify interruptions.
5. **Standardized Reporting**:
   - Produces standalone, self-contained HTML forensic reports adhering to **ISO/IEC 27037:2012** and **ISO/IEC 27042:2015**.
   - Embeds interactive 2D/3D flight maps, event logs, hash certificates, and examiner sign-offs with zero external internet dependencies.
   - Exports to JSON and DFXML (Digital Forensics XML).

---

### 2. Forensic RAG Subsystem (AI Forensic Analyst)

The toolkit features a specialized **Retrieval-Augmented Generation (RAG)** engine designed specifically for UAV criminal and incident investigations:

- **Isolated Case Collections**: Each forensic case maintains a private, cryptographically segregated ChromaDB collection (`case_<case_id>`), eliminating cross-case contamination.
- **Domain-Aware Forensic Chunking**:
  - `telemetry_summary`: Flight boundaries, max altitude, peak ground speed, arm/disarm events.
  - `geofence_breach`: Altitude violations, Red Zone perimeter intrusions, dwell duration, and GPS coordinates.
  - `sensor_anomaly`: GPS jumps, compass errors, sudden battery drops, and motor disarms.
  - `chain_of_custody`: SHA-256/SHA-3 hashes, write-block verification, and examiner audit trail.
  - `operator_gcs`: Pilot profile, GCS software version, home location, and planned waypoints.
  - `regulation_standard`: Statutory grounding in DGCA Drone Rules 2021, FAA 14 CFR Part 107, and ISO standards.
- **Multi-Tier Resilience Routing**:
  1. **Primary**: Ultra-fast cloud inference via **Groq Cloud API** (`llama-3.3-70b-versatile`).
  2. **Air-Gapped Fallback**: Local **Ollama** daemon (`http://localhost:11434` with `llama3` or `mistral`) for classified, air-gapped forensic environments.
  3. **Offline Deterministic Fallback**: Grounded forensic evidence extraction that ensures 100% operational uptime even without API keys or local LLM instances.
- **Strict Anti-Hallucination Prompting**: Mandates explicit citations of UTC timestamps, GPS coordinates, severity levels, and regulatory provisions.

---

### 3. Multi-Source Evidence & Platform Support

| Drone Platform | Supported Formats | Extracted Forensic Artifacts |
|---|---|---|
| **DJI** | `.DAT` (v1/v2/v3), `.txt`, `.srt` | GPS trajectory, barometric altitude, attitude (roll/pitch/yaw), battery voltage, motor RPMs, RTH home position, video telemetry sync |
| **ArduPilot** | `.bin` (DataFlash), `.log`, `.tlog` | POS/GPS messages, flight modes (AUTO, RTL, LOITER), arming flags, parameter changes, MAVLink telemetry streams |
| **PX4 Autopilot** | `.ulg` (ULog binary), `.csv` | Native ULog topics (`vehicle_gps_position`, `vehicle_status`), failsafe triggers, actuator controls, sensor clipping |
| **Parrot** | `.pud`, `.json` | Bebop & Anafi flight records, battery discharge curves, motor stall warnings, controller link quality |
| **Betaflight / iNav** | `.bbl` (Blackbox), `.txt` | High-frequency gyro/accel rates, motor commands, arming switch states, failsafe activations, navigation waypoints |
| **Ground Control** | `.plan`, `.waypoints`, `.kml`, `.param` | Planned routes, waypoint coordinates, planned altitudes, operator home fixes, GCS software identifiers |
| **Mobile Apps** | Android `.db`/backups, iOS `.plist`/archives | Pilot accounts, email, aircraft serial numbers, remote controller IDs, pilot phone GPS coordinates |
| **Aerial Media** | `.jpg`, `.jpeg`, `.mp4`, `.mov` | EXIF GPS IFD tags, camera sensor model, rational coordinate decoding, embedded video subtitle streams (`.srt`) |

#### Extending Support for Custom Drone Formats (`dft/plugins/base.py`)

For investigators and developers encountering drone models or proprietary flight record formats not supported out-of-the-box (e.g., Autel, Skydio, custom enterprise UAVs, or proprietary blackboxes), **[`dft/plugins/base.py`](dft/plugins/base.py)** provides an **editable, standardized base class** (`DroneForensicPlugin`).

Anyone with a different or new drone format can easily implement custom parsing by subclassing this interface:

```python
from pathlib import Path
from typing import List, Dict, Any
from dft.plugins.base import DroneForensicPlugin
from dft.core.models import TelemetryPoint, FlightEvent

class CustomDronePlugin(DroneForensicPlugin):
    @property
    def platform_id(self) -> str:
        return "custom_uav"  # Unique machine identifier

    @property
    def display_name(self) -> str:
        return "Custom UAV Platform"

    @property
    def supported_extensions(self) -> List[str]:
        return [".bin", ".log", ".dat", ".json"]

    def detect(self, file_path: Path) -> bool:
        # Signature/magic-byte or header check to identify this format
        with open(file_path, "rb") as f:
            header = f.read(16)
            return b"CUSTOM_HEADER" in header

    def parse_telemetry(self, file_path: Path) -> List[TelemetryPoint]:
        # Extract and normalize timestamp, lat, lon, alt, speed, roll/pitch/yaw
        points = []
        # e.g., points.append(TelemetryPoint(timestamp=..., latitude=..., longitude=...))
        return points

    def parse_events(self, file_path: Path) -> List[FlightEvent]:
        # Extract discrete flight events (arm, disarm, failsafe, mode changes, waypoints)
        return []

    def extract_metadata(self, file_path: Path) -> Dict[str, Any]:
        # Extract flight controller serial number, firmware version, drone model
        return {"platform": "custom_uav", "serial": "UNKNOWN"}
```

##### How to Enable Your Custom Plugin:
1. **Edit or Subclass**: Inherit from `DroneForensicPlugin` in [`dft/plugins/base.py`](dft/plugins/base.py) or create a new parser module under `dft/plugins/`.
2. **Register**: Add your class instance to `self._plugins` in [`dft/plugins/manager.py`](dft/plugins/manager.py) (or invoke `manager.register_plugin(CustomDronePlugin())`).
3. **Verify**: Run `python dft/cli.py plugins` to see your new platform registered in the active parser registry. The Web Dashboard, REST API, and CLI will automatically route your file format through the complete 5-layer forensic pipeline!

---

### 4. Ground Control Station (GCS) Audit

The GCS analysis engine (`dft/analysis/gcs.py`) investigates operator-side evidence:
- **Supported Stations**: QGroundControl, Mission Planner, DJI Pilot / Assistant, Autel Explorer, and Parrot FreeFlight.
- **Waypoint Schedule Extraction**: Recovers sequential planned waypoints (lat, lon, planned altitude, command type, loiter time).
- **Operator Geolocation Recovery**: Extracts operator station coordinates from GCS headers and MAVLink `HOME_POSITION` / `MISSION_ITEM` messages.
- **Trajectory vs. Plan Comparison**: Automatically computes route deviation (mean and max deviation in meters), percentage compliance score, and identifies if the mission was intentionally aborted or hijacked.

---

### 5. Mobile Companion App Forensics

The mobile forensics module (`dft/analysis/mobile.py`) inspects mobile device evidence (smartphones, tablets, smart controllers):
- **Supported Companion Apps**: DJI Fly, DJI Go 4, Autel Explorer, Parrot FreeFlight 6/7, and QGroundControl Mobile.
- **Pilot Account Extraction**: Recovers registered pilot names, usernames, callsigns, and registered emails.
- **Paired Hardware Identification**: Recovers aircraft serial number, camera gimbal serial number, and remote controller pairing ID.
- **Operator Device Location**: Extracts the pilot's physical phone/tablet GPS location at takeoff and during flight.

---

### 6. Forensic Wireless Acquisition

The wireless module (`dft/acquisition/wireless.py`) enables non-invasive, over-the-air capture from UAVs in field scenarios:
- **Wi-Fi AP Direct Extraction (`WIFI_FTP`)**: Connects to drone access points (e.g., Parrot, DJI, custom APs) and retrieves flight records and media over FTP/HTTP without physical teardown.
- **MAVLink UDP Stream Capture (`MAVLINK_UDP`)**: Captures live broadcast telemetry over UDP port 14550/14555 and saves forensic `.tlog` and PCAP records.
- **Wireless ADB Dump (`WIRELESS_ADB`)**: Pulls flight controller and companion Android system logs over network ADB.
- **Cryptographic Chaining**: All acquired wireless sessions generate dual SHA-256/SHA-3-256 manifests instantly upon session close.

---

### 7. Aerial Media & Video Telemetry Extractor

The media module (`dft/analysis/media.py` & `dft/analysis/media_import.py`) correlates imagery and video with flight events:
- **EXIF Geotag Extraction**: Parses standard EXIF IFD GPS tags, converting rational degrees/minutes/seconds into high-precision decimal coordinates.
- **Video Subtitle Stream Telemetry**: Extracts embedded `.srt` subtitle data from DJI and Autel MP4/MOV recordings.
- **Spatial-Temporal Correlation**: Aligns media capture timestamps with flight controller telemetry, allowing examiners to pinpoint exactly where the drone was located when a specific photo or video frame was captured.

---

### 8. Geofencing & Airspace Regulatory Engine

The geofence module (`dft/analysis/geofence.py` & `dft/analysis/restricted_spaces.py`) evaluates flight paths against airspace regulations:
- **Pre-Loaded National Airspace Catalogs**:
  - **DGCA Drone Rules 2021 (India)**:
    - **Red Zones**: International borders (5km buffer), airports/aerodromes (3km buffer), military bases, government secretariats, and nuclear installations.
    - **Yellow Zones**: 8km–12km airport perimeter buffers and airspace above 400 ft (120m) in green zones.
    - **Green Zones**: Unrestricted airspace up to 400 ft AGL.
  - **FAA 14 CFR Part 107 (US)**: Class B/C/D controlled airspaces, critical infrastructure, and 400 ft altitude ceiling.
- **Custom Investigator Geofences**: Interactive polygon drawing, circular exclusion zones, minimum/maximum altitude thresholds, and active time windows.
- **Automated Breach Detection**: Flags exact entry timestamp, exit timestamp, maximum intrusion altitude, and breach duration.

---

## Quickstart & Installation

### Prerequisites
- Python 3.10 or higher
- Git
- Recommended: Virtual environment (`venv` or `conda`)

### 1. Clone & Setup Environment
```bash
# Clone the repository
git clone https://github.com/Backwardbus03/drone-sec.git
cd drone-sec

# Create and activate virtual environment
python -m venv venv

# Windows:
.\venv\Scripts\activate

# Linux / macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Optional LLM API Keys (for RAG)
DFT works completely offline with built-in heuristics, but for full conversational AI synthesis:
```bash
# Option A: Groq Cloud API (Recommended for fastest cloud inference)
export GROQ_API_KEY="gsk_your_groq_api_key_here"

# Option B: Local Ollama (For air-gapped / local inference)
# 1. Install and start Ollama (https://ollama.ai)
# 2. Run: ollama run llama3
# DFT will automatically detect Ollama at http://localhost:11434
```

### 3. Run Test Suite
Validate the installation by running the comprehensive automated test suite:
```bash
# Run all unit and integration tests
pytest -v

# Run RAG subsystem tests specifically
pytest -v tests/test_rag.py
```

---

## Interactive Web Dashboard

Launch the unified investigation console:
```bash
python dft/cli.py serve --port 8000
```
Open your browser at **[http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)**:

- **Tactical Dark UI**: High-contrast, clean interface built for forensic operations.
- **Interactive Leaflet Map**: 2D/3D flight trajectory rendering, takeoff/landing points, geofence polygons, and media geotags.
- **Geofence Manager**: Visual polygon editor with one-click presets (DGCA Red Zones, Airport Airspace, Military Bases).
- **Multi-Track Timeline**: Synchronized visualization of flight events, sensor anomalies, GCS commands, and media captures.
- **Evidence Vault**: Real-time write-block status, dual cryptographic hashes, and Expert Witness Format (`.E01`) export.
- **AI Forensic Analyst (RAG)**: Natural-language investigation assistant with suggested prompts, live evidence indexing, and citation badges.
- **One-Click Sample Loaders**: Instant loading of DJI Mavic 3, ArduPilot, PX4, Parrot Anafi, and Betaflight sample cases.
- **Court Report Generator**: One-click generation of standalone, court-admissible HTML examination reports.

---

## Complete CLI Reference

DFT provides a comprehensive Command-Line Interface (`dft/cli.py`) supporting 12 subcommands:

```bash
python dft/cli.py <command> [options]
```

### Command Summary

| Subcommand | Description | Primary Flags & Arguments |
|---|---|---|
| `serve` | Launch FastAPI interactive Web Console | `--host 127.0.0.1`, `--port 8000` |
| `hash` | Compute dual cryptographic hashes (SHA-256 + SHA-3) & verify write-blocking | `<file>` |
| `parse` | Parse drone evidence, extract telemetry, detect breaches & anomalies | `<file>` |
| `report` | Generate standalone ISO 27037 forensic court report | `<file>`, `--out <path>`, `--examiner <name>`, `--case <id>` |
| `gcs` | Audit GCS mission plans, waypoints, and flight plan adherence | `<file>`, `--flight-log <path>` |
| `mobile` | Inspect mobile companion backups, pilot profiles, and operator GPS | `<target>`, `--list-apps` |
| `wireless` | Perform over-the-air acquisition from drone APs or MAVLink UDP | `--mode [WIFI_FTP\|MAVLINK_UDP\|WIRELESS_ADB]`, `--ip <ip>`, `--port <port>`, `--out <dir>` |
| `plugins` | List all registered drone platform parsers and extensions | *(none)* |
| `benchmark` | Inspect reference benchmark datasets and run validation suite | `--run`, `--dataset <id>`, `--fetch-real-data` |
| `classify` | Inspect and categorize evidence file into Logs, Video/Images, or GCS | `<file>` |
| `ask` | Query case evidence in natural language using Forensic RAG | `<case_id>`, `"<question>"`, `--top-k 8` |
| `rag-ingest` | Vectorize and index an evidence file into ChromaDB | `<file>`, `--case-id <id>` |

### Detailed Usage Examples

#### 1. Launch Web Console
```bash
python dft/cli.py serve --port 8000
```

#### 2. Dual Cryptographic Hashing with Write-Block Verification
```bash
python dft/cli.py hash samples/dji_mavic3_telemetry.srt
```

#### 3. Parse Flight Log & Detect Violations
```bash
python dft/cli.py parse samples/ardupilot_flight.log
```

#### 4. Generate Court-Admissible ISO 27037 Forensic Report
```bash
python dft/cli.py report samples/px4_mission.csv --out examination_report.html --examiner "Special Agent Sharma" --case "CASE-2026-UAV-001"
```

#### 5. Ground Control Station (GCS) Audit & Mission Adherence
```bash
# Audit planned waypoints and operator location
python dft/cli.py gcs samples/px4_survey.plan

# Compare planned mission vs. actual flown trajectory
python dft/cli.py gcs samples/px4_survey.plan --flight-log samples/px4_mission.csv
```

#### 6. Mobile Companion Forensics
```bash
# List all supported drone companion applications
python dft/cli.py mobile --list-apps

# Analyze mobile evidence directory or backup archive
python dft/cli.py mobile evidence_vault/mobile_backup.zip
```

#### 7. Forensic Wireless Acquisition
```bash
# Acquire logs from drone Wi-Fi Access Point over FTP
python dft/cli.py wireless --mode WIFI_FTP --ip 192.168.42.1 --platform Parrot --out evidence_vault/wireless

# Capture live MAVLink telemetry stream over UDP
python dft/cli.py wireless --mode MAVLINK_UDP --port 14550 --out evidence_vault/wireless
```

#### 8. Evidence File Classification
```bash
python dft/cli.py classify samples/dji_mavic3_telemetry.srt
```

#### 9. Forensic RAG: Ingestion & Natural-Language Q&A
```bash
# 1. Index evidence into case vector store
python dft/cli.py rag-ingest samples/ardupilot_flight.log --case-id CASE-001

# 2. Query evidence using AI Forensic Analyst
python dft/cli.py ask CASE-001 "Did the drone violate any DGCA red zones or exceed 400ft altitude?"

# 3. Inquire about sensor anomalies and failsafes
python dft/cli.py ask CASE-001 "Were there any sudden battery drops or motor disarm events during the flight?"
```

#### 10. Reference Forensic Benchmark Evaluation
```bash
# List all 7 registered benchmark datasets and specifications
python dft/cli.py benchmark

# Download genuine open-access research flight datasets
python dft/cli.py benchmark --fetch-real-data

# Execute automated validation suite (verifies 100% pass across all 7 suites)
python dft/cli.py benchmark --run

# Run a specific benchmark suite
python dft/cli.py benchmark --run --dataset ardupilot-flight-suite
```

---

## REST API Reference

DFT exposes an asynchronous REST API built with FastAPI. Interactive OpenAPI/Swagger documentation is available at **`http://127.0.0.1:8000/docs`**.

### Core Endpoints

#### Case Management & Audit Trail
- `POST /api/cases` — Create a new forensic case with metadata.
- `GET /api/cases` — List all active forensic cases.
- `GET /api/cases/{case_id}` — Get case metadata, summary, and timestamps.
- `GET /api/cases/{case_id}/audit-trail` — Retrieve HMAC-verified append-only chain of custody audit logs.

#### Evidence & Media Acquisition
- `POST /api/cases/{case_id}/ingest` — Upload and ingest flight logs or telemetry files with automated write-blocking.
- `POST /api/cases/{case_id}/ingest-media` — Ingest aerial imagery or video files and extract EXIF/subtitle metadata.
- `GET /api/cases/{case_id}/evidence` — List all evidence items registered to the case with dual hash manifests.
- `GET /api/cases/{case_id}/media` — Retrieve extracted aerial media items with GPS geotags.
- `GET /api/cases/{case_id}/media/{item_id}/e01` — Export evidence file as an Expert Witness Format (`.E01`) image.

#### Telemetry & Trajectory Reconstruction
- `GET /api/cases/{case_id}/telemetry` — Retrieve parsed telemetry points (time, lat, lon, alt, speed, roll/pitch/yaw).
- `GET /api/cases/{case_id}/geojson` — Export flight path as standard GeoJSON `LineString` and `Point` features.
- `GET /api/cases/{case_id}/kml` — Export 3D flight trajectory as Google Earth KML with altitude extrusion.
- `GET /api/cases/{case_id}/summary` — Retrieve high-level flight statistics (max alt, total distance, arm times).

#### Ground Control Station & Mobile Forensics
- `GET /api/cases/{case_id}/gcs` — Retrieve GCS audit result, planned waypoints, and flight plan adherence metrics.
- `GET /api/gcs/supported-stations` — Catalog of supported GCS platforms.
- `GET /api/cases/{case_id}/mobile` — Retrieve companion app artifacts, pilot account, and paired hardware serial numbers.
- `GET /api/mobile/supported-apps` — Catalog of supported companion mobile applications.

#### Wireless Acquisition
- `GET /api/wireless/supported-modes` — List wireless acquisition modes (`WIFI_FTP`, `MAVLINK_UDP`, `WIRELESS_ADB`).
- `POST /api/cases/{case_id}/wireless/acquire` — Trigger wireless acquisition session from drone AP or MAVLink stream.

#### Geofencing & Airspace Compliance
- `GET /api/geofence/catalog` — Pre-loaded catalog of national airspace zones (DGCA Red/Yellow/Green, FAA).
- `GET /api/cases/{case_id}/geofence/zones` — Get active geofence zones for a case.
- `POST /api/cases/{case_id}/geofence/zones` — Register custom polygon or cylindrical geofence zone.
- `POST /api/cases/{case_id}/geofence/load-all-presets` — Load all DGCA statutory airspace zones into the case.
- `GET /api/cases/{case_id}/geofence/violations` — Evaluate and retrieve all detected geofence breaches.

#### AI Forensic Analyst (RAG)
- `POST /api/cases/{case_id}/rag/ingest` — Vectorize and index case telemetry, breaches, anomalies, and logs into ChromaDB.
- `POST /api/cases/{case_id}/ask` — Submit natural-language investigative question and receive grounded forensic analysis with source citations.
- `GET /api/cases/{case_id}/rag/status` — Inspect vector index status, total chunks, and LLM provider availability.

#### Forensic Reporting
- `GET /api/cases/{case_id}/report/html` — Generate and stream standalone ISO 27037 HTML examination report.
- `GET /api/cases/{case_id}/report/json` — Export complete case examination in machine-readable JSON format.
- `GET /api/cases/{case_id}/report/dfxml` — Export case metadata in Digital Forensics XML (DFXML) format.

#### Forensic Benchmarks
- `GET /api/benchmarks` — List all 7 reference forensic benchmark suites and academic citations.
- `POST /api/benchmarks/run` — Run automated benchmark validation suite.
- `POST /api/benchmarks/fetch-real-data` — Download genuine reference datasets from public repositories.

---

## Reference Forensic Benchmark Suites

The toolkit's forensic soundness, integrity, and reconstruction capabilities are validated against **seven peer-reviewed and open-source benchmark suites**:

| Benchmark Suite | Academic Citation / Source | Target Platforms | Key Evidence Tested | Primary Validated Layer |
|---|---|---|---|---|
| **1. VTO Labs Drone Forensic Program** | [NIH PMC10293979](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC10293979/) / NIST CFReDS | DJI (Phantom 3/4, Mavic, Inspire), Yuneec, Parrot | Bit-stream disk images (`.dd`, `.E01`), NAND flash dumps, encrypted storage, file carving | **Layer 1** (Acquisition) & **Layer 2** (Preservation) |
| **2. DJI Phantom III (DROP)** | [Springer](https://link.springer.com/chapter/10.1007/978-3-031-93511-4_7) / Clark et al. | DJI Phantom 3 (Standard, Advanced, Pro) | Flight controller `.DAT` binary records, internal micro-USB dumps, cached mobile records | **Layer 3** (DJI Parser) & **Layer 4** (Timeline Engine) |
| **3. AirData UAV Flight Logs** | [GitHub DroneNLP](https://github.com/DroneNLP/dataset) (499 messages) | DJI Mavic/Phantom, Autel, Skydio, Parrot | Multi-UAV CSV/JSON telemetry, trajectory tracks, 499 flight incident warning messages | **Layer 4** (Flight Path & Geofence Engine) |
| **4. DroSev / DroNER Dataset** | [PubMed Central PMC12877856](https://pmc.ncbi.nlm.nih.gov/articles/PMC12877856/) / Mendeley Data | Multi-vendor industrial UAVs | Standardized flight logs with 4-tier ground truth severities (Info, Warning, Error, Critical) | **Layer 4** (Anomaly Engine) & **Layer 5** (Reporting) |
| **5. ArduPilot Autonomous Suite** | [ArduPilot.org Flight Archive](https://ardupilot.org) / IEEE UAV Studies | ArduCopter, ArduPlane, ArduVTOL, Pixhawk | DataFlash binary logs (`.bin`, `.log`), MAVLink telemetry (`.tlog`), parameter dumps | **Layer 3** (ArduPilot Parser) & **Layer 4** (Mission Trajectory) |
| **6. PX4 Autopilot / CMU ALFA** | [logs.px4.io](https://logs.px4.io) & CMU ALFA (Field Robotics) | PX4 Autopilot, Pixhawk FMUv4/v5/v6 | Native binary ULog (`.ulg`), topic streams, in-flight actuator faults, failsafe triggers | **Layer 3** (PX4 Parser) & **Layer 4** (Hardware Faults) |
| **7. UAV Aerial Media & Video Suite** | [OpenDroneMap / SenseFly](https://github.com/OpenDroneMap/odm_data_bellus) | Commercial survey & camera UAVs (eBee, Mavic 3) | High-res aerial survey imagery, EXIF GPS IFD tags, rational degrees, video subtitle telemetry (`.srt`) | **Layer 3** (Media Extractor) & **Layer 4** (Spatial Correlation) |

Execute the benchmark evaluation suite at any time:
```bash
python dft/cli.py benchmark --run
```

---

## Directory Structure

```
drone-sec/
├── README.md                      # Comprehensive toolkit documentation
├── pyproject.toml                 # Package configuration & metadata
├── requirements.txt               # Production & research dependencies
├── overview.md                    # IIT Bombay Techfest Grand Challenge specifications
├── stage_1_preliminary_design.md  # Architectural specification & preliminary design
├── dft/                           # Core Drone Forensic Toolkit package
│   ├── cli.py                     # Unified Command-Line Interface (12 subcommands)
│   ├── acquisition/               # Layer 1: Forensic Acquisition Engine
│   │   ├── physical.py            # Bit-stream disk imaging (.dd)
│   │   ├── e01.py                 # Expert Witness Format (.E01) generator
│   │   ├── logical.py             # Logical extraction & partition dumper
│   │   ├── carver.py              # Deleted flight log file carver
│   │   ├── mobile.py              # Android ADB & iOS backup extractor
│   │   ├── wireless.py            # Wi-Fi AP FTP, MAVLink UDP, wireless ADB
│   │   └── network.py             # PCAP network packet capture
│   ├── core/                      # Layer 2: Forensic Preservation Engine
│   │   ├── hashing.py             # Dual SHA-256 + SHA-3-256 cryptographic hashing
│   │   ├── write_blocker.py       # Software canary write-blocking verification
│   │   ├── chain_of_custody.py    # HMAC-SHA256 append-only tamper-evident audit ledger
│   │   ├── classifier.py          # Evidence auto-classifier (Logs / Media / GCS)
│   │   └── models.py              # Canonical Pydantic data schemas & telemetry models
│   ├── plugins/                   # Layer 3: Vendor-Neutral Multi-Platform Parsers
│   │   ├── manager.py             # Dynamic plugin registration & routing manager
│   │   ├── base.py                # Abstract base plugin interface (editable base for custom drone formats)
│   │   ├── dji.py                 # DJI .DAT, .txt, and .srt telemetry parser
│   │   ├── ardupilot.py           # ArduPilot DataFlash .bin, .log, and .tlog parser
│   │   ├── px4.py                 # PX4 native binary ULog (.ulg) & .csv parser
│   │   ├── parrot.py              # Parrot Bebop/Anafi .pud & JSON parser
│   │   └── betaflight.py          # Betaflight & iNav Blackbox (.bbl) parser
│   ├── analysis/                  # Layer 4: Forensic Analysis & Spatial Reconstruction
│   │   ├── timeline.py            # Synchronized UTC chronological timeline engine
│   │   ├── flight_path.py         # 2D/3D Trajectory calculator & KML/GeoJSON exporter
│   │   ├── geofence.py            # Geofence breach & spatial containment engine
│   │   ├── restricted_spaces.py   # DGCA Drone Rules 2021 & FAA airspace zone catalogs
│   │   ├── anomaly.py             # Anti-forensics, sensor anomalies & failsafe detector
│   │   ├── gcs.py                 # Ground Control Station audit & mission adherence
│   │   ├── mobile.py              # Companion mobile application forensic analyzer
│   │   ├── media.py               # EXIF geotag & video subtitle stream parser
│   │   └── media_import.py        # Media batch processor & spatial-temporal correlator
│   ├── rag/                       # Layer 5: AI Forensic RAG Subsystem
│   │   ├── chunker.py             # Domain-aware forensic evidence chunker
│   │   ├── embedder.py            # Semantic sentence & TF-IDF vector embedder
│   │   ├── vector_store.py        # Isolated per-case ChromaDB vector collections
│   │   ├── regulations.py         # Statutory grounding (DGCA 2021, FAA 107, ISO 27037)
│   │   ├── llm.py                 # Groq LLaMA-3.3 + Ollama + Offline resilience router
│   │   ├── query.py               # Forensic RAG prompt context & retrieval engine
│   │   └── ingest.py              # Automated case evidence ingestion pipeline
│   ├── reporting/                 # Layer 5: Court-Admissible Reporting Engine
│   │   └── generator.py           # ISO 27037 standalone HTML, JSON & DFXML generator
│   ├── api/                       # REST API Backend
│   │   └── app.py                 # FastAPI application with complete route endpoints
│   ├── web/                       # Web Dashboard Frontend
│   │   ├── dashboard.html         # Main tactical forensic investigation console
│   │   ├── mobile_upload.html     # Dedicated mobile companion upload portal
│   │   ├── css/styles.css         # Dark tactical forensic UI styling
│   │   └── js/                    # Modular ES6 frontend components
│   │       ├── app.js             # State management & dashboard controller
│   │       ├── rag.js             # AI Forensic Analyst chat & indexing controller
│   │       ├── map.js             # Leaflet map & trajectory layer renderer
│   │       ├── geofence.js        # Geofence zone manager & polygon editor
│   │       ├── timeline.js        # Unified UTC timeline visualizer
│   │       ├── evidence.js        # Evidence vault & hash verification table
│   │       ├── media.js           # Media gallery & EXIF inspector
│   │       ├── gcs.js             # GCS mission plan auditor & adherence viewer
│   │       └── mobile.js          # Mobile companion artifacts & pilot profile viewer
│   └── benchmarks/                # Reference Benchmark Validation Framework
│       ├── registry.py            # 7 benchmark specifications & academic citations
│       ├── evaluator.py           # Automated evaluation runner & scoring engine
│       └── downloader.py          # Public research dataset fetcher
├── samples/                       # Multi-platform sample evidence files
│   ├── ardupilot_flight.log       # ArduPilot DataFlash flight log
│   ├── ardupilot_mission.waypoints# ArduPilot waypoint mission plan
│   ├── ardupilot_telemetry.tlog   # MAVLink telemetry packet stream
│   ├── betaflight_blackbox.txt    # Betaflight Blackbox gyro/motor log
│   ├── dji_mavic3_telemetry.srt   # DJI Mavic 3 video subtitle telemetry
│   ├── dji_pilot2_mission.kml     # DJI Pilot 2 planned mission KML
│   ├── inav_autonomous.mission    # iNav autonomous survey mission
│   ├── parrot_anafi_flight.json   # Parrot Anafi telemetry recording
│   ├── parrot_flightplan.mavlink  # Parrot flight plan definition
│   ├── px4_mission.csv            # PX4 ULog exported telemetry
│   ├── px4_survey.plan            # QGroundControl autonomous survey plan
│   ├── sample_aerial_photo.jpg    # Aerial survey photo with EXIF GPS IFD tags
│   └── sample_recon_video.mp4     # Reconnaissance video with embedded subtitles
└── tests/                         # Comprehensive automated test suite
    ├── test_api.py                # REST API endpoint tests
    ├── test_benchmarks.py         # Benchmark suite tests
    ├── test_dashboard_flow.py     # Web dashboard workflow tests
    ├── test_evidence_sorting.py   # Evidence classification tests
    ├── test_forensics.py          # Core forensic parsing & hashing tests
    ├── test_gcs.py                # GCS mission plan & adherence tests
    ├── test_geofence_real_world.py# DGCA & FAA geofencing tests
    ├── test_media_import.py       # Aerial media & EXIF tests
    ├── test_mobile_apps.py        # Mobile companion forensics tests
    └── test_rag.py                # Forensic RAG ingestion & Q&A tests
```

---

## Legal Admissibility & Forensic Soundness

DFT is engineered to meet the strictest standards of legal defensibility in judicial proceedings:

1. **ISO/IEC 27037:2012 Compliance**:
   - **Auditability**: Every examiner action is immutably logged to an HMAC-SHA256 audit ledger.
   - **Repeatability**: Running DFT on duplicate bit-stream images yields bit-for-bit identical telemetry, timelines, and cryptographic hashes.
   - **Reproducibility**: Exported DFXML and raw CSVs allow independent verification using third-party open-source forensic utilities.
   - **Justifiability**: All parsing algorithms, geofence evaluations, and anomaly thresholds are deterministic, vendor-neutral, and fully open-source.
2. **ISO/IEC 27042:2015 Compliance**:
   - Establishes a standardized framework for the analysis and interpretation of UAV incident data, sensor discrepancies, and operator intent.
3. **Indian Evidence Act / Bharatiya Sakshya Adhiniyam (BSA)**:
   - Designed to support Section 65B (or Section 63 of BSA) electronic record admissibility certificates by generating complete cryptographic hash manifests, machine environment snapshots, and unbroken chain of custody records.
4. **Air-Gapped Operation**:
   - Complete functionality operates without internet connectivity. All maps, parsing libraries, cryptographic engines, and fallback LLM summarizers run 100% locally.

---

## Citation & Academic Attribution

If you utilize the Drone Forensic Toolkit (DFT) or its reference benchmark suites in your research or forensic casework, please cite:

```bibtex
@misc{dft2026,
  author       = {Backwardbus03},
  title        = {Drone Forensic Toolkit (DFT): Indigenous, Modular Digital Forensic Framework for UAV Investigations},
  howpublished = {IIT Bombay Techfest Grand Challenge: Objective 1},
  year         = {2026},
  url          = {https://github.com/Backwardbus03/drone-sec}
}
```

---

*Developed for the IIT Bombay Techfest Grand Challenge: Objective 1.*
