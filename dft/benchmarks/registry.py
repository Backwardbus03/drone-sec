"""
Benchmark Registry for Drone Forensic Toolkit (DFT).
Defines reference datasets, academic citations, target UAV platforms, evidence formats,
and evaluation metrics for forensic verification under controlled test conditions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional


class BenchmarkCategory(str, Enum):
    PHYSICAL_ACQUISITION_CARVING = "PHYSICAL_ACQUISITION_CARVING"
    PROPRIETARY_INTERNAL = "PROPRIETARY_INTERNAL"
    CLOUD_FLEET_TELEMETRY = "CLOUD_FLEET_TELEMETRY"
    ANOMALY_SEVERITY_NLP = "ANOMALY_SEVERITY_NLP"
    OPEN_SOURCE_AUTOPILOT = "OPEN_SOURCE_AUTOPILOT"
    HARDWARE_FAULT_FAILSAFE = "HARDWARE_FAULT_FAILSAFE"
    AERIAL_MEDIA_METADATA = "AERIAL_MEDIA_METADATA"


@dataclass
class BenchmarkMetric:
    metric_id: str
    name: str
    target_threshold: str
    unit: str
    description: str


@dataclass
class BenchmarkSampleCase:
    case_id: str
    name: str
    platform: str
    evidence_type: str
    description: str
    ground_truth_summary: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BenchmarkDataset:
    id: str
    name: str
    short_title: str
    category: BenchmarkCategory
    citation: str
    reference_url: str
    source_organization: str
    target_platforms: List[str]
    evidence_types: List[str]
    toolkit_layers: List[str]
    evaluation_criteria_mapping: str
    description: str
    forensic_challenges: List[str]
    metrics: List[BenchmarkMetric]
    sample_cases: List[BenchmarkSampleCase]


BENCHMARK_REGISTRY: Dict[str, BenchmarkDataset] = {
    "vto-labs-drone-program": BenchmarkDataset(
        id="vto-labs-drone-program",
        name="VTO Labs Drone Forensic Program Reference Dataset",
        short_title="VTO Labs Drone Forensic Images",
        category=BenchmarkCategory.PHYSICAL_ACQUISITION_CARVING,
        citation="VTO Labs & DHS/NIST. Forensic Analysis of Drone Video Data & CFReDS Reference Images. NIH PMC10293979 (2023).",
        reference_url="https://www.ncbi.nlm.nih.gov/pmc/articles/PMC10293979/",
        source_organization="VTO Labs / NIST Computer Forensic Reference Data Sets (CFReDS)",
        target_platforms=[
            "DJI Phantom 3 / 4",
            "DJI Mavic Pro / Mavic Air",
            "DJI Inspire 1 / 2",
            "DJI Spark",
            "DJI Matrice",
            "Yuneec Typhoon",
            "Parrot Bebop / Anafi"
        ],
        evidence_types=[
            "Forensic bit-stream disk images (.dd, .raw, .E01)",
            "NAND flash physical extractions",
            "Encrypted flight records (.DAT)",
            "Unallocated space file fragments (JPEG, MP4, ULog)",
            "Companion mobile application backup images (Android/iOS)"
        ],
        toolkit_layers=[
            "Layer 1 — Evidence Acquisition (Physical Disk Imaging)",
            "Layer 2 — Evidence Preservation (Cryptographic Hashing & Write-Blocking)",
            "Layer 3 — Parsing & Extraction (File Carving & Decryption Routines)"
        ],
        evaluation_criteria_mapping="Multi-platform acquisition (20%) + Evidence integrity & hashing (20%)",
        description=(
            "The most widely used benchmark source in digital drone forensics, providing raw forensic "
            "disk and memory images acquired from commercial and enthusiast UAVs. Encrypted volumes "
            "and unallocated blocks allow rigorous validation of software write-blocking, bit-exact "
            "imaging, cryptographic dual-hash verification, and signature-based file carving."
        ),
        forensic_challenges=[
            "Encrypted onboard eMMC storage on modern DJI aircraft",
            "Proprietary partition tables and FAT32/exFAT filesystem corruption",
            "Fragmented media files in unallocated sectors requiring carving",
            "Strict read-only write-blocking verification during block reading"
        ],
        metrics=[
            BenchmarkMetric("hash_verif_acc", "Dual-Hash Cryptographic Accuracy", "100.0", "%", "Exact match for SHA-256 and SHA-3-256 against reference manifests"),
            BenchmarkMetric("write_block_verif", "Canary Write-Inhibition Success Rate", "100.0", "%", "Zero write leaks permitted before acquisition"),
            BenchmarkMetric("carve_recovery_rate", "File Carving Header/Footer Recovery", ">= 95.0", "%", "Percentage of embedded media and logs successfully carved")
        ],
        sample_cases=[
            BenchmarkSampleCase(
                case_id="VTO-DJI-P4-001",
                name="DJI Phantom 4 MicroSD Physical Disk Image",
                platform="DJI",
                evidence_type="RAW_DD_IMAGE",
                description="64GB MicroSD physical disk image with unallocated sectors and deleted flight photos.",
                ground_truth_summary={"expected_files_carved": ["JPEG_PHOTO", "PX4_ULOG"], "write_blocked": True}
            )
        ]
    ),

    "drop-dji-phantom3": BenchmarkDataset(
        id="drop-dji-phantom3",
        name="DJI Phantom III Forensic Dataset (DROP)",
        short_title="DROP Phantom III Dataset",
        category=BenchmarkCategory.PROPRIETARY_INTERNAL,
        citation="D.R. Clark, C. Zou, B. Baggili. 'DROP (DRone Open source Parser) your drone: forensic analysis of the DJI Phantom III', Digital Investigation 22, S3–S14 (2017). Springer 978-3-031-93511-4_7.",
        reference_url="https://link.springer.com/chapter/10.1007/978-3-031-93511-4_7",
        source_organization="Cyber Forensic Research & Education Group (UNH) / Springer",
        target_platforms=[
            "DJI Phantom 3 Standard",
            "DJI Phantom 3 Advanced",
            "DJI Phantom 3 Professional"
        ],
        evidence_types=[
            "Flight controller proprietary .DAT binary records",
            "Internal micro-USB data dumps from flight controller",
            "MicroSD FAT32 media and video SRT subtitle streams",
            "Mobile device cached flight logs (DJI GO .txt)",
            "Home point coordinates and take-off GPS fixes"
        ],
        toolkit_layers=[
            "Layer 3 — Parsing & Extraction (DJI Flight Controller Parser)",
            "Layer 4 — Analysis & Reconstruction (Timeline Reconstruction & Flight Path Analyzer)"
        ],
        evaluation_criteria_mapping="Recovery of logs, telemetry, GPS & media (20%) + Extensibility (5%)",
        description=(
            "A foundational, peer-reviewed drone forensic dataset established in the DROP project. "
            "Provides ground-truth flight logs and internal flash dumps from DJI Phantom III drones, "
            "documenting proprietary binary record structures, motor status fields, GPS fixes, and "
            "mobile application synchronization artifacts."
        ),
        forensic_challenges=[
            "Reverse-engineering binary record headers and telemetry structures",
            "Correlating flight controller .DAT records with video SRT subtitles",
            "Extracting accurate home-point and return-to-home (RTH) coordinates",
            "Reconstructing exact flight trajectories with zero spatial deviation"
        ],
        metrics=[
            BenchmarkMetric("waypoint_coord_precision", "GPS Waypoint Extraction Precision", "100.0", "%", "Zero geospatial coordinate translation error"),
            BenchmarkMetric("event_correlation_accuracy", "Cross-Source Event Correlation", ">= 98.0", "%", "Accurate correlation between flight log and video timestamps"),
            BenchmarkMetric("timeline_continuity", "Timeline Chronological Continuity", "100.0", "%", "All chronological events correctly ordered in UTC")
        ],
        sample_cases=[
            BenchmarkSampleCase(
                case_id="DROP-P3-DAT-01",
                name="Phantom 3 Controlled Waypoint Flight",
                platform="DJI",
                evidence_type="DJI_TELEMETRY_LOG",
                description="Controlled flight with 12 waypoints, video recording, and return-to-home trigger.",
                ground_truth_summary={"waypoints_count": 12, "events_identified": ["ARM", "TAKEOFF", "RTH", "LAND"]}
            )
        ]
    ),

    "airdata-uav-logs": BenchmarkDataset(
        id="airdata-uav-logs",
        name="AirData UAV Flight Telemetry & 499 Message Corpus",
        short_title="AirData UAV Fleet Telemetry",
        category=BenchmarkCategory.CLOUD_FLEET_TELEMETRY,
        citation="DroneNLP / AirData UAV. Large-Scale Multi-UAV Flight Telemetry & 499 In-Flight Messages Dataset. GitHub DroneNLP/dataset (2024).",
        reference_url="https://github.com/DroneNLP/dataset",
        source_organization="AirData UAV / DroneNLP Open Research",
        target_platforms=[
            "DJI Mavic 2 / Mavic 3 / Mini",
            "DJI Phantom 4 Pro",
            "Autel Robotics EVO II",
            "Skydio 2 / X2",
            "Parrot Anafi Enterprise",
            "SenseFly eBee X"
        ],
        evidence_types=[
            "High-frequency CSV/JSON multi-drone telemetry streams",
            "Geodetic trajectory tracks (Latitude, Longitude, Altitude, Velocity)",
            "Battery discharge and cell temperature logs",
            "Control signal RSSI and uplink/downlink telemetry",
            "Original collection of 499 structured in-flight warning messages"
        ],
        toolkit_layers=[
            "Layer 4 — Analysis & Reconstruction (Flight Path Analyzer & Geofence Engine)",
            "Layer 5 — Reporting & Export (3D KML/KMZ Google Earth Visualization)"
        ],
        evaluation_criteria_mapping="Completeness of forensic reporting (15%) + Usability & automation (10%)",
        description=(
            "Extensive repository of real-world multi-model UAV flight missions. Encompasses commercial "
            "and enterprise drone flights across multiple countries, featuring 499 discrete status and "
            "warning messages. Used to validate high-throughput telemetry ingestion, speed/altitude "
            "profiling, and geofence collision detection against real airport boundaries."
        ),
        forensic_challenges=[
            "Ingesting heterogenous telemetry schemas across diverse manufacturers",
            "Accurate geospatial boundary collision detection across complex polygons",
            "Handling sensor jitter and GPS multipath artifacts in urban canyons",
            "Automated generation of 3D flight paths compatible with Google Earth"
        ],
        metrics=[
            BenchmarkMetric("geofence_precision", "Geofence Breach Detection Precision", "100.0", "%", "No false positives when evaluating spatial and altitude fences"),
            BenchmarkMetric("geofence_recall", "Geofence Breach Detection Recall", "100.0", "%", "All boundary intrusions and ceiling breaches flagged"),
            BenchmarkMetric("kml_export_validity", "3D KML Export Schema Compliance", "100.0", "%", "Flawless rendering in Google Earth and GIS platforms")
        ],
        sample_cases=[
            BenchmarkSampleCase(
                case_id="AIRDATA-MULTI-499",
                name="AirData 499 Incident Messages Corpus",
                platform="Multi-Vendor",
                evidence_type="CSV_TELEMETRY_STREAM",
                description="499 flight messages spanning battery warnings, compass errors, and boundary alerts.",
                ground_truth_summary={"total_messages": 499, "categories": ["BATTERY", "COMPASS", "AIRSPACE", "FAILSAFE"]}
            )
        ]
    ),

    "drosev-droner-mendeley": BenchmarkDataset(
        id="drosev-droner-mendeley",
        name="DroSev / DroNER Curated Drone Forensic Benchmark",
        short_title="DroSev / DroNER Dataset",
        category=BenchmarkCategory.ANOMALY_SEVERITY_NLP,
        citation="Curated Drone Flight Log Dataset on Mendeley Data / PubMed Central PMC12877856 (2025). Severity Classification and Named Entity Recognition for Drone Flight Logs.",
        reference_url="https://pmc.ncbi.nlm.nih.gov/articles/PMC12877856/",
        source_organization="Mendeley Data / National Library of Medicine (PMC12877856)",
        target_platforms=[
            "Industrial Multirotors",
            "Agriculture & Spraying Drones",
            "Infrastructure Inspection UAVs",
            "Surveillance & Security Drones"
        ],
        evidence_types=[
            "Curated flight log message records derived from VTO Labs and AirData",
            "Standardized 4-tier severity classifications (Info, Warning, Error, Critical)",
            "Named Entity Recognition (NER) annotations for drone components, sensors, and actions",
            "Documented flight failure and emergency landing incident records"
        ],
        toolkit_layers=[
            "Layer 4 — Analysis & Reconstruction (Anomaly & Anti-Forensics Detector)",
            "Layer 5 — Reporting & Export (Structured ISO 27042 Legal Evidence Matrix)"
        ],
        evaluation_criteria_mapping="Completeness of forensic reporting (15%) + Evidence recovery (20%)",
        description=(
            "A curated and standardized benchmark dataset specifically designed for forensic log "
            "analysis and anomaly severity classification. Aggregated from VTO Labs and AirData sources, "
            "it establishes ground-truth severity tiers and semantic entity labels across diverse drone "
            "models in industrial sectors."
        ),
        forensic_challenges=[
            "Mapping non-standardized proprietary error strings to normalized severity levels",
            "Distinguishing routine pilot commands from anti-forensic log tampering or clock skew",
            "Correlating critical error triggers with emergency motor shutdown events",
            "Synthesizing structured court-admissible finding sections without bias"
        ],
        metrics=[
            BenchmarkMetric("severity_match_acc", "Anomaly Severity Tier Accuracy", ">= 96.0", "%", "Correct classification into Info, Warning, Error, or Critical"),
            BenchmarkMetric("tamper_detection_f1", "Anti-Forensics / Clock Skew F1-Score", ">= 98.0", "%", "Detection of timestamp reversals, missing sequence numbers, and gaps"),
            BenchmarkMetric("iso_report_compliance", "ISO/IEC 27042 Reporting Conformance", "100.0", "%", "All required legal findings and audit trails populated")
        ],
        sample_cases=[
            BenchmarkSampleCase(
                case_id="DROSEV-ANOMALY-01",
                name="In-Flight Motor Stall & Unexpected Disarm",
                platform="Multi-Vendor",
                evidence_type="ANNOTATED_ERROR_LOG",
                description="Mid-air disarm accompanied by voltage drop and abnormal attitude excursion.",
                ground_truth_summary={"expected_severity": "CRITICAL", "anomaly_type": "UNEXPECTED_DISARM"}
            )
        ]
    ),

    "ardupilot-flight-suite": BenchmarkDataset(
        id="ardupilot-flight-suite",
        name="ArduPilot Autonomous Flight & Anomaly Benchmark",
        short_title="ArduPilot DataFlash & MAVLink Suite",
        category=BenchmarkCategory.OPEN_SOURCE_AUTOPILOT,
        citation="ArduPilot Development Team & Open Flight Archive. DataFlash binary log repository and MAVLink telemetry benchmark suite. IEEE UAV Forensics & Cyber-Physical Safety Studies (2024).",
        reference_url="https://ardupilot.org/copter/docs/common-downloading-and-analyzing-data-logs-in-mission-planner.html",
        source_organization="ArduPilot Open Source Community / IEEE UAV Forensics",
        target_platforms=[
            "ArduCopter (Quadcopter, Hexacopter, Octocopter)",
            "ArduPlane (Fixed-Wing UAVs)",
            "ArduVTOL (Hybrid Vertical Takeoff)",
            "Pixhawk 1/2/4/6X, Cube Orange/Black Flight Controllers"
        ],
        evidence_types=[
            "DataFlash binary logs (.bin, .log) containing FMT, PARM, GPS, POS, ATT, MODE, ERR records",
            "MAVLink telemetry packet streams (.tlog)",
            "Onboard waypoint mission files and mission planner parameter dumps (.param)",
            "EKF3 sensor fusion discrepancy logs (GPS vs IMU vs Compass)",
            "Documented flight failure modes (failsafe RTL, battery failsafe, geofence breaches)"
        ],
        toolkit_layers=[
            "Layer 3 — Parsing & Extraction (ArduPilot DataFlash & MAVLink Parser)",
            "Layer 4 — Analysis & Reconstruction (Autonomous Mission Trajectory & GPS Spoofing Detection)"
        ],
        evaluation_criteria_mapping="Extensibility to open-source UAVs (5%) + Recovery of logs, telemetry & GPS (20%)",
        description=(
            "The authoritative benchmark for open-source autopilot forensics. DataFlash logs capture "
            "comprehensive microsecond-resolution vehicle states, from pre-arm safety checks to waypoint "
            "navigation and autonomous failsafes. Validates binary FMT schema parsing, flight mode "
            "transition extraction (STABILIZE -> AUTO -> RTL), and sensor tampering detection."
        ),
        forensic_challenges=[
            "Decoding dynamic message schemas defined in FMT header packets",
            "Extracting high-frequency EKF state estimates and attitude quaternions",
            "Detecting GPS spoofing or clock drift via sensor discordance (GPS vs Barometer/IMU)",
            "Parsing autonomous waypoint missions and verifying route compliance"
        ],
        metrics=[
            BenchmarkMetric("fmt_schema_decode_rate", "FMT Schema Packet Decoding Rate", "100.0", "%", "Zero unknown packet drops for standard DataFlash message types"),
            BenchmarkMetric("flight_mode_transition_acc", "Flight Mode Sequence Identification", "100.0", "%", "Accurate identification of all STABILIZE, AUTO, RTL, and LAND phases"),
            BenchmarkMetric("sensor_spoof_detection", "GPS/Baro Discordance Detection", ">= 95.0", "%", "Flagging artificial coordinate jumps or barometric deviations")
        ],
        sample_cases=[
            BenchmarkSampleCase(
                case_id="ARDU-WAYPOINT-01",
                name="Autonomous Grid Survey Mission with Failsafe RTL",
                platform="ArduPilot",
                evidence_type="DATAFLASH_LOG",
                description="Autonomous lawnmower survey flight with simulated battery failsafe triggering RTL.",
                ground_truth_summary={
                    "flight_modes": ["ARM", "TAKEOFF", "AUTO", "RTL", "DISARM"],
                    "waypoints": 8,
                    "failsafe_triggered": True
                }
            )
        ]
    ),

    "px4-alfa-anomaly-suite": BenchmarkDataset(
        id="px4-alfa-anomaly-suite",
        name="PX4 Autopilot / ALFA Flight Anomaly & ULog Benchmark",
        short_title="PX4 ULog & CMU ALFA Dataset",
        category=BenchmarkCategory.HARDWARE_FAULT_FAILSAFE,
        citation="Dronecode Foundation (logs.px4.io) & Keipour et al., 'ALFA: A Dataset for UAV Fault and Anomaly Detection', CMU AirLab / Field Robotics / arXiv:2009.07427 (2021).",
        reference_url="https://logs.px4.io",
        source_organization="Dronecode Foundation (PX4) / Carnegie Mellon University AirLab",
        target_platforms=[
            "PX4 Autopilot (v1.12+)",
            "Pixhawk FMUv4 / FMUv5 / FMUv6X",
            "Fixed-Wing, Multirotor, and Tiltrotor UAVs"
        ],
        evidence_types=[
            "Native ULog binary flight logs (.ulg) with subscription topic streams",
            "vehicle_gps_position, vehicle_status, vehicle_attitude, sensor_combined topics",
            "Documented in-flight hardware faults: aileron jam, rudder loss, motor thrust loss",
            "Commander state transitions and emergency failsafe parachute/land activations",
            "EKF2 innovation and variance diagnostic streams"
        ],
        toolkit_layers=[
            "Layer 3 — Parsing & Extraction (PX4 ULog Binary Parser)",
            "Layer 4 — Analysis & Reconstruction (Actuator Fault & In-Flight Anomaly Correlation)",
            "Layer 5 — Reporting & Export (ISO 27037/27042 Legal Findings Synthesis)"
        ],
        evaluation_criteria_mapping="Multi-platform acquisition & parsing (20%) + Completeness of forensic reporting (15%)",
        description=(
            "A premier benchmark for autonomous UAV fault analysis and ULog forensic decoding. "
            "Combines thousands of real-world flights from the Dronecode Flight-Review repository with "
            "the CMU ALFA dataset of intentional, controlled in-flight hardware faults. Validates ULog "
            "binary parsing, actuator anomaly detection, and court-admissible reporting under severe "
            "incident conditions."
        ),
        forensic_challenges=[
            "Parsing self-describing binary ULog message structures with dynamic types",
            "Correlating sudden vehicle attitude divergence with actuator saturation",
            "Extracting commander arming states and identifying exact timestamp of pilot overrides",
            "Reconstructing failure sequences leading to emergency touchdown or crash"
        ],
        metrics=[
            BenchmarkMetric("ulog_topic_decode_acc", "ULog Topic Extraction Accuracy", "100.0", "%", "Flawless extraction of vehicle_gps_position and status topics"),
            BenchmarkMetric("hardware_fault_detection", "Actuator Fault Detection Sensitivity", ">= 95.0", "%", "Identification of abnormal control surface or motor failure"),
            BenchmarkMetric("failsafe_timestamp_prec", "Failsafe Timestamp Resolution", "<= 0.1", "sec", "Precision in identifying exact moment of emergency failsafe trigger")
        ],
        sample_cases=[
            BenchmarkSampleCase(
                case_id="PX4-ALFA-MOTOR-01",
                name="PX4 In-Flight Motor Failure & Auto-Land",
                platform="PX4",
                evidence_type="ULOG_BINARY",
                description="Controlled multicopter flight experiencing motor #3 thrust loss followed by auto-land.",
                ground_truth_summary={
                    "fault_type": "ACTUATOR_MOTOR_LOSS",
                    "fault_timestamp_sec": 142.5,
                    "failsafe_action": "EMERGENCY_DESCENT"
                }
            )
        ]
    ),

    "uav-media-exif-video-suite": BenchmarkDataset(
        id="uav-media-exif-video-suite",
        name="UAV Aerial Photo EXIF & Video Telemetry Benchmark",
        short_title="Drone Photos & Video Metadata Suite",
        category=BenchmarkCategory.AERIAL_MEDIA_METADATA,
        citation="OpenDroneMap (ODM) & Digital Investigation Aerial Media Corpus. Photogrammetric and Forensic Drone EXIF/XMP Dataset (2024).",
        reference_url="https://github.com/OpenDroneMap/odm_data_bellus",
        source_organization="OpenDroneMap / DJI Developer Video Telemetry Standard",
        target_platforms=[
            "SenseFly eBee / eMotion",
            "DJI Phantom 3 / 4 / Mavic",
            "Canon / Sony Airborne Survey Payloads"
        ],
        evidence_types=[
            "JPEG aerial photos with EXIF GPS tags (GPSLatitude, GPSLongitude, GPSAltitude)",
            "Drone-specific camera metadata (Make, Model, Software, ProcessingSoftware)",
            "Video companion subtitle telemetry (.srt) with per-frame GPS and attitude",
            "XMP photogrammetric gimbal tags (pitch, roll, yaw, flight track)"
        ],
        toolkit_layers=[
            "Layer 3 — Parsing & Extraction (Metadata Extractor)",
            "Layer 4 — Analysis & Reconstruction (Cross-Source Correlator & 3D Flight Path Pinning)"
        ],
        evaluation_criteria_mapping="Ability to recover logs, telemetry, GPS & media (20%) + Completeness of reporting (15%)",
        description=(
            "Validates extraction of forensic metadata from drone aerial photography and video assets. "
            "Tests extraction of geodetic coordinates (WGS-84), barometric/ellipsoidal altitudes, "
            "camera specifications, and frame-by-frame video subtitle telemetry for cross-source "
            "correlation against flight controller logs."
        ),
        forensic_challenges=[
            "Parsing non-standard rational EXIF coordinate structures without precision loss",
            "Decoding drone ground-station signatures embedded in software tags",
            "Cross-correlating photo capture timestamps with flight log GPS fixes",
            "Synchronizing video subtitle frames with UAV trajectory waypoints"
        ],
        metrics=[
            BenchmarkMetric("exif_gps_extraction_acc", "EXIF GPS Coordinate Extraction Accuracy", "100.0", "%", "Zero geospatial coordinate translation error from EXIF tags"),
            BenchmarkMetric("camera_model_identification", "Drone Camera/Software Identification", "100.0", "%", "Correct extraction of camera make, model, and drone software tags"),
            BenchmarkMetric("video_telemetry_frame_sync", "Video Subtitle Frame-Level Extraction", "100.0", "%", "Flawless parsing of SRT companion video telemetry streams")
        ],
        sample_cases=[
            BenchmarkSampleCase(
                case_id="MEDIA-PHOTO-EBEE-01",
                name="SenseFly eBee Drone Aerial Survey Photo",
                platform="SenseFly eBee",
                evidence_type="JPEG_EXIF_IMAGE",
                description="Real aerial photo captured by SenseFly eBee drone with Canon S110 payload.",
                ground_truth_summary={
                    "camera_make": "Canon",
                    "camera_model": "Canon PowerShot S110",
                    "software": "eBee",
                    "latitude": 41.2256725,
                    "longitude": -81.7025348,
                    "altitude_m": 442.64
                }
            )
        ]
    )
}


def get_benchmark_by_id(benchmark_id: str) -> Optional[BenchmarkDataset]:
    return BENCHMARK_REGISTRY.get(benchmark_id)


def list_benchmarks() -> List[BenchmarkDataset]:
    return list(BENCHMARK_REGISTRY.values())
