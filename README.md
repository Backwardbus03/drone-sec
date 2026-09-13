# Drone Forensic Toolkit (DFT)
**Indigenous, Modular Digital Forensic Framework for UAV Investigations**
*Developed for the IIT Bombay Techfest Grand Challenge: Objective 1*

---

## Features

- **5-Layer Architecture**:
  1. **Acquisition**: Software-only write-blocked acquisition via laptop ports (USB, SD/microSD, Wi-Fi monitor mode).
  2. **Preservation**: Dual cryptographic hashing (**SHA-256 + SHA-3-256**) and tamper-evident append-only **Chain of Custody (HMAC-SHA256)**.
  3. **Parsing**: Vendor-neutral plugin engine supporting **DJI, ArduPilot, PX4 Autopilot, Parrot, and Betaflight/iNav**.
  4. **Analysis**: Unified UTC timeline, 2D/3D trajectory rendering, **investigator-configurable geofencing** (custom polygons, altitude ceilings, temporal windows), and anti-forensics anomaly detection.
  5. **Reporting**: Court-admissible forensic reporting complying with **ISO/IEC 27037:2012** and **ISO/IEC 27042:2015**. Exportable to PDF, HTML, JSON, DFXML, and 3D Google Earth KML.

---

## Quickstart

### 1. Launch Web Console
```bash
# Launch interactive investigation console
python dft/cli.py serve --port 8000
```
Open your browser at [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard) to access the interactive investigation console with live Leaflet map, geofence manager, timeline reconstructor, and one-click sample loaders!

### 2. Command-Line Interface (CLI)
```bash
# List supported drone platforms
python dft/cli.py plugins

# Compute dual hashes with write-block check
python dft/cli.py hash samples/dji_mavic3_telemetry.srt

# Parse telemetry and detect geofence/anomalies
python dft/cli.py parse samples/ardupilot_flight.log

# Generate standalone ISO 27037 court report
python dft/cli.py report samples/px4_mission.csv --out examination_report.html
```

### 3. Run Automated Tests
```bash
pytest -v
```

---

## Platform Support
| Platform | Format Supported | Capabilities |
|---|---|---|
| **DJI** | `.DAT`, `.txt`, `.srt` | GPS, attitude, video telemetry sync, battery status |
| **ArduPilot** | `.bin`, `.log`, `.tlog` | DataFlash GPS/POS, modes, arming events, parameters |
| **PX4** | `.ulg`, `.csv` | Native ULog binary, vehicle GPS, failsafe states |
| **Parrot** | `.pud`, `.json` | Anafi/Bebop telemetry points, sensor metrics |
| **Betaflight / iNav** | `.bbl`, `.txt` | Blackbox gyro/motor logs, GPS coordinates, arm switches |

---

## Reference Forensic Benchmark Datasets

The toolkit's forensic soundness, integrity, and reconstruction capabilities are validated against **seven peer-reviewed and open-source benchmark suites**:

| Benchmark Suite | Source & Academic Citation | Target Platforms | Key Evidence Tested | Primary Validated Layer |
|---|---|---|---|---|
| **1. VTO Labs Drone Forensic Program** | [NIH PMC10293979](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC10293979/) / NIST CFReDS | DJI (Phantom 3/4, Mavic, Inspire), Yuneec, Parrot | Bit-stream disk images (`.dd`, `.E01`), NAND flash dumps, encrypted storage, file carving | **Layer 1** (Acquisition) & **Layer 2** (Preservation) |
| **2. DJI Phantom III (DROP)** | [Springer](https://link.springer.com/chapter/10.1007/978-3-031-93511-4_7) / Clark et al., *Digital Investigation* | DJI Phantom 3 (Standard, Advanced, Pro) | Flight controller `.DAT` binary records, internal micro-USB dumps, cached mobile records | **Layer 3** (DJI Parser) & **Layer 4** (Timeline Engine) |
| **3. AirData UAV Flight Logs** | [GitHub DroneNLP](https://github.com/DroneNLP/dataset) (499 messages) | DJI Mavic/Phantom, Autel, Skydio, Parrot | Multi-UAV CSV/JSON telemetry, trajectory tracks, 499 flight incident warning messages | **Layer 4** (Flight Path & Geofence Engine) |
| **4. DroSev / DroNER Dataset** | [PubMed Central PMC12877856](https://pmc.ncbi.nlm.nih.gov/articles/PMC12877856/) / Mendeley Data | Multi-vendor industrial UAVs | Standardized flight logs with 4-tier ground truth severities (Info, Warning, Error, Critical) | **Layer 4** (Anomaly Engine) & **Layer 5** (Reporting) |
| **5. ArduPilot Autonomous Suite** | [ArduPilot.org Flight Archive](https://ardupilot.org) / IEEE UAV Studies | ArduCopter, ArduPlane, ArduVTOL, Pixhawk | DataFlash binary logs (`.bin`, `.log`), MAVLink telemetry (`.tlog`), parameter dumps | **Layer 3** (ArduPilot Parser) & **Layer 4** (Mission Trajectory) |
| **6. PX4 Autopilot / CMU ALFA** | [logs.px4.io](https://logs.px4.io) & CMU ALFA (Field Robotics) | PX4 Autopilot, Pixhawk FMUv4/v5/v6 | Native binary ULog (`.ulg`), topic streams, in-flight actuator faults, failsafe triggers | **Layer 3** (PX4 Parser) & **Layer 4** (Hardware Faults) |
| **7. UAV Aerial Media & Video Suite** | [OpenDroneMap / SenseFly](https://github.com/OpenDroneMap/odm_data_bellus) & Commercial Fleets | Commercial survey & camera UAVs (eBee, Mavic 3) | High-res aerial survey imagery, EXIF GPS IFD tags, rational degrees, video subtitle telemetry (`.srt`) | **Layer 3** (Media Extractor) & **Layer 4** (Spatial Correlation) |

### Benchmark CLI Commands
```bash
# List all 7 benchmark specifications, academic citations, and evaluation layers
python dft/cli.py benchmark

# Download genuine reference datasets into benchmarks/data/ (VTO Labs, AirData CSV, PX4 ULog, eBee Photo)
python dft/cli.py benchmark --fetch-real-data

# Execute automated benchmark evaluation suite (verifies 100% pass across all 7 suites)
python dft/cli.py benchmark --run

# Run specific benchmark suite (e.g. ArduPilot, PX4, or Media)
python dft/cli.py benchmark --run --dataset ardupilot-flight-suite
python dft/cli.py benchmark --run --dataset px4-alfa-anomaly-suite
python dft/cli.py benchmark --run --dataset uav-media-exif-video-suite
```

### Benchmark REST API Endpoints
- `GET /api/benchmarks` — List all 7 registered reference benchmark datasets and evaluation metrics.
- `GET /api/benchmarks/{benchmark_id}` — Inspect detailed specification of a single benchmark suite.
- `POST /api/benchmarks/run` — Run automated validation suite and receive scored JSON scorecard.
- `POST /api/benchmarks/fetch-real-data` — Trigger download or verification of genuine benchmark datasets.


