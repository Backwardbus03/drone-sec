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
