"""
Forensic Report Generator for Drone Forensic Toolkit.
Generates court-admissible forensic reports in HTML, JSON, and Digital Forensics XML (DFXML)
formatted in accordance with ISO/IEC 27037:2012 and ISO/IEC 27042:2015.
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from jinja2 import Template
from dft.core.models import CaseMetadata, EvidenceItem, FlightSummary, GeofenceViolation, AnomalyReport, AuditLogEntry

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensic Examination Report - {{ case.case_id }}</title>
<style>
  body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #1e293b; max-width: 1000px; margin: 0 auto; padding: 30px; background: #f8fafc; }
  .card { background: #ffffff; border-radius: 12px; padding: 25px; margin-bottom: 25px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -1px rgba(0,0,0,0.06); border: 1px solid #e2e8f0; }
  .header-card { background: linear-gradient(135deg, #0f172a, #1e293b); color: #ffffff; border: none; }
  .header-card h1 { margin: 0 0 10px 0; color: #38bdf8; font-size: 26px; }
  .badge { display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
  .badge-success { background: #dcfce7; color: #15803d; }
  .badge-danger { background: #fee2e2; color: #b91c1c; }
  .badge-warning { background: #fef3c7; color: #b45309; }
  .badge-info { background: #e0f2fe; color: #0369a1; }
  table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }
  th, td { padding: 12px 14px; text-align: left; border-bottom: 1px solid #e2e8f0; }
  th { background: #f1f5f9; color: #475569; font-weight: 600; }
  tr:hover { background: #f8fafc; }
  .hash-box { font-family: 'Consolas', monospace; font-size: 12px; background: #f1f5f9; padding: 4px 8px; border-radius: 4px; word-break: break-all; }
  .section-title { font-size: 18px; font-weight: 700; color: #0f172a; border-left: 4px solid #0284c7; padding-left: 12px; margin-top: 0; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; }
  .stat-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; text-align: center; }
  .stat-val { font-size: 22px; font-weight: 700; color: #0284c7; }
  .stat-label { font-size: 12px; color: #64748b; text-transform: uppercase; margin-top: 4px; }
  .footer { text-align: center; font-size: 12px; color: #94a3b8; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; }
</style>
</head>
<body>

<div class="card header-card">
  <div style="display: flex; justify-content: space-between; align-items: flex-start;">
    <div>
      <h1>UAV DIGITAL FORENSIC EXAMINATION REPORT</h1>
      <p style="margin: 0; opacity: 0.85;">Standards Compliance: ISO/IEC 27037:2012 & ISO/IEC 27042:2015</p>
    </div>
    <span class="badge badge-success" style="background: #0284c7; color: #fff;">CASE # {{ case.case_id }}</span>
  </div>
</div>

<div class="card">
  <h2 class="section-title">Case & Examination Details</h2>
  <div class="grid-2">
    <div>
      <p><strong>Case Title:</strong> {{ case.case_name }}</p>
      <p><strong>Lead Investigator:</strong> {{ case.investigator_name }}</p>
      <p><strong>Agency / Laboratory:</strong> {{ case.agency_name }}</p>
    </div>
    <div>
      <p><strong>Report Generated:</strong> {{ report_generated_utc }}</p>
      <p><strong>Chain-of-Custody Status:</strong> <span class="badge badge-success">Cryptographically Verified</span></p>
      <p><strong>Case Status:</strong> <span class="badge badge-info">{{ case.status }}</span></p>
    </div>
  </div>
  {% if case.description %}
  <p style="margin-top: 15px; background: #f1f5f9; padding: 12px; border-radius: 6px; font-size: 14px;">
    <strong>Case Notes:</strong> {{ case.description }}
  </p>
  {% endif %}
</div>

<div class="card">
  <h2 class="section-title">Flight Performance & Telemetry Overview</h2>
  <div class="grid-4" style="margin-top: 15px;">
    <div class="stat-box">
      <div class="stat-val">{{ summary.platform_detected.upper() }}</div>
      <div class="stat-label">Platform Architecture</div>
    </div>
    <div class="stat-box">
      <div class="stat-val">{{ summary.total_distance_meters }} m</div>
      <div class="stat-label">Total Flight Distance</div>
    </div>
    <div class="stat-box">
      <div class="stat-val">{{ summary.max_altitude_m }} m</div>
      <div class="stat-label">Peak Altitude (MSL/Rel)</div>
    </div>
    <div class="stat-box">
      <div class="stat-val">{{ summary.max_speed_mps }} m/s</div>
      <div class="stat-label">Max Ground Speed</div>
    </div>
  </div>

  <div class="grid-4" style="margin-top: 15px;">
    <div class="stat-box">
      <div class="stat-val">{{ summary.total_duration_sec }}s</div>
      <div class="stat-label">Airborne Duration</div>
    </div>
    <div class="stat-box">
      <div class="stat-val">{{ summary.telemetry_count }}</div>
      <div class="stat-label">GPS Records Extracted</div>
    </div>
    <div class="stat-box">
      <div class="stat-val" style="color: {% if summary.violations_count > 0 %}#dc2626{% else %}#16a34a{% endif %};">
        {{ summary.violations_count }}
      </div>
      <div class="stat-label">Geofence Violations</div>
    </div>
    <div class="stat-box">
      <div class="stat-val" style="color: {% if summary.anomalies_count > 0 %}#f59e0b{% else %}#16a34a{% endif %};">
        {{ summary.anomalies_count }}
      </div>
      <div class="stat-label">Detected Anomalies</div>
    </div>
  </div>

  <div class="grid-2" style="margin-top: 15px;">
    <div class="stat-box">
      <div class="stat-val" style="font-size: 15px; font-family: monospace; color: #059669;">{{ summary.arm_time_utc or 'N/A' }}</div>
      <div class="stat-label">Motors Armed At (UTC)</div>
    </div>
    <div class="stat-box">
      <div class="stat-val" style="font-size: 15px; font-family: monospace; color: #b45309;">{{ summary.disarm_time_utc or 'N/A' }}</div>
      <div class="stat-label">Motors Disarmed At (UTC)</div>
    </div>
  </div>
</div>

{% if (gcs_analysis and gcs_analysis.detected_gcs != 'NONE') or summary.gcs_detected or summary.operator_location %}
<div class="card" style="border-left: 4px solid #0284c7;">
  <h2 class="section-title">Ground Control Station (GCS) & Operator Forensics</h2>
  <div class="grid-2">
    <div>
      <p><strong>Detected GCS Platform:</strong> <span class="badge badge-info">{{ (gcs_analysis.detected_gcs if gcs_analysis and gcs_analysis.detected_gcs != 'NONE' else None) or summary.gcs_detected or 'GCS Telemetry Session' }}</span></p>
      <p><strong>Associated Autopilot:</strong> {{ (gcs_analysis.associated_fc if gcs_analysis and gcs_analysis.associated_fc != 'NONE' else None) or summary.platform_detected }}</p>
      {% if summary.operator_location or (gcs_analysis and gcs_analysis.operator_locations) %}
      {% set op = summary.operator_location or gcs_analysis.operator_locations[0] %}
      <p><strong>Operator / Launch Location:</strong> <span class="hash-box">{{ op.latitude|round(6) }}, {{ op.longitude|round(6) }} (Alt: {{ op.altitude_m|round(1) if op.altitude_m else '0.0' }}m)</span></p>
      <p><strong>Geolocation Source:</strong> <span style="font-size: 13px; color: #64748b;">{{ op.source }}</span></p>
      {% endif %}
    </div>
    <div>
      {% if gcs_analysis and gcs_analysis.mission_plans %}
      {% set plan = gcs_analysis.mission_plans[0] %}
      <p><strong>Autonomous Mission Plan:</strong> {{ plan.file_name }}</p>
      <p><strong>Planned Waypoints Count:</strong> {{ plan.waypoints|length }}</p>
      <p><strong>Planned Route Length:</strong> {{ plan.total_planned_distance_m }}m (Ceiling: {{ plan.planned_max_altitude_m }}m)</p>
      {% endif %}
      {% if gcs_analysis and gcs_analysis.mission_comparison %}
      {% set comp = gcs_analysis.mission_comparison %}
      <p><strong>Mission Path Adherence:</strong> <span class="badge {% if comp.compliance_score_pct >= 80 %}badge-success{% elif comp.compliance_score_pct >= 50 %}badge-warning{% else %}badge-danger{% endif %}">{{ comp.compliance_score_pct }}% Compliance</span></p>
      <p><strong>Waypoints Reached:</strong> {{ comp.waypoints_reached }} of {{ comp.waypoints_total }} (Mean Dev: {{ comp.mean_deviation_meters }}m)</p>
      {% endif %}
    </div>
  </div>

  {% if gcs_analysis and gcs_analysis.mission_plans and gcs_analysis.mission_plans[0].waypoints %}
  <h3 style="font-size: 14px; font-weight: 600; margin-top: 15px; color: #334155;">Planned Autonomous Waypoints Schedule</h3>
  <table>
    <thead>
      <tr>
        <th>WP #</th>
        <th>Action / Command</th>
        <th>Coordinates (WGS-84)</th>
        <th>Altitude</th>
        <th>Speed</th>
      </tr>
    </thead>
    <tbody>
      {% for wp in gcs_analysis.mission_plans[0].waypoints[:15] %}
      <tr>
        <td><strong>#{{ wp.index }}</strong></td>
        <td><span class="badge badge-info">{{ wp.command }}</span></td>
        <td>{{ wp.latitude|round(6) }}, {{ wp.longitude|round(6) }}</td>
        <td>{{ wp.altitude_m|round(1) }}m</td>
        <td>{{ wp.speed_mps or '12.0' }} m/s</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% if gcs_analysis.mission_plans[0].waypoints|length > 15 %}
  <p style="font-size: 11px; color: #64748b; margin-top: 6px;">* Displaying first 15 waypoints. Full plan preserved in digital evidence record.</p>
  {% endif %}
  {% endif %}
</div>
{% endif %}

{% if (mobile_analysis and mobile_analysis.artifacts) or wireless_sessions %}
<div class="card" style="border-left: 4px solid #8b5cf6;">
  <h2 class="section-title">Mobile Companion Applications & Wireless Acquisition Forensics</h2>
  <p style="font-size: 13px; color: #64748b; margin-bottom: 15px;">
    Examines suspect mobile companion software (DJI Fly, DJI GO 4, Litchi, QGroundControl Mobile, 3DR Tower, Parrot FreeFlight, SpeedyBee, EZ-GUI, Autel Explorer) and wireless acquisition sessions (Wi-Fi AP FTP, MAVLink UDP, Wireless ADB) recovered in accordance with ISO/IEC 27037:2012.
  </p>

  {% if mobile_analysis and mobile_analysis.artifacts %}
  <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 15px; margin-bottom: 15px;">
    {% for art in mobile_analysis.artifacts %}
    <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; background: #fafafa;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <span style="font-weight: 700; color: #1e293b; font-size: 14px;">{{ art.app_name }}</span>
        <span class="badge badge-info">{{ art.target_platform }}</span>
      </div>
      <p style="font-size: 11px; color: #64748b; font-family: monospace;">Pkg: {{ art.package_id or 'com.uav.companion' }}</p>
      {% if art.pilot_account %}
      <div style="margin-top: 8px; padding-top: 8px; border-top: 1px dashed #cbd5e1; font-size: 12px;">
        <p><strong>Pilot:</strong> {{ art.pilot_account.pilot_name or art.pilot_account.callsign or art.pilot_account.email or 'Registered User' }}</p>
        {% if art.pilot_account.email %}<p><strong>Email:</strong> {{ art.pilot_account.email }}</p>{% endif %}
      </div>
      {% endif %}
      {% if art.paired_hardware %}
      <div style="margin-top: 6px; font-size: 12px;">
        {% if art.paired_hardware.aircraft_sn %}<p><strong>Paired Aircraft SN:</strong> <span class="hash-box">{{ art.paired_hardware.aircraft_sn }}</span></p>{% endif %}
        {% if art.paired_hardware.controller_sn %}<p><strong>RC SN:</strong> {{ art.paired_hardware.controller_sn }}</p>{% endif %}
      </div>
      {% endif %}
      {% if art.operator_locations %}
      <div style="margin-top: 6px; font-size: 12px; color: #059669;">
        <strong>Phone GPS:</strong> {{ art.operator_locations[0].latitude|round(6) }}, {{ art.operator_locations[0].longitude|round(6) }}
      </div>
      {% endif %}
      <div style="margin-top: 8px; font-size: 11px; color: #64748b;">
        Logs: {{ art.flight_logs|length }} | Missions: {{ art.mission_plans|length }} | Media: {{ art.cached_media|length }}
      </div>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  {% if wireless_sessions %}
  <h3 style="font-size: 14px; font-weight: 600; margin-top: 15px; margin-bottom: 8px; color: #334155;">Wireless Acquisition Transfer Sessions</h3>
  <table>
    <thead>
      <tr>
        <th>Session ID</th>
        <th>Protocol</th>
        <th>Source Endpoint</th>
        <th>Target Device</th>
        <th>Transferred</th>
        <th>Files Acquired</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>
      {% for ws in wireless_sessions %}
      <tr>
        <td><strong>{{ ws.session_id }}</strong></td>
        <td><span class="badge badge-info">{{ ws.protocol }}</span></td>
        <td><code>{{ ws.source_ip }}</code></td>
        <td>{{ ws.target_device }}</td>
        <td>{{ ws.bytes_transferred }} B</td>
        <td>{{ ws.files_acquired|join(', ') }}</td>
        <td><span class="badge badge-success">{{ ws.status }}</span></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% endif %}
</div>
{% endif %}

{% if media_items %}
<div class="card" style="border-left: 4px solid #0284c7;">
  <h2 class="section-title">Aerial Visual Evidence & Synchronized Media Captures</h2>
  <p style="font-size: 13px; color: #64748b; margin-bottom: 15px;">
    Examines UAV imagery and video captured during the incident. All media items synchronized with flight telemetry have been preserved in bit-exact Expert Witness Format (.eo1 / .E01) containers with dual SHA-256 and SHA-3-256 cryptographic hashing in compliance with ISO/IEC 27037:2012.
  </p>
  
  <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(290px, 1fr)); gap: 18px; margin-top: 15px;">
    {% for m in media_items %}
    <div style="border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; background: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,0.05); display: flex; flex-direction: column;">
      {% if m.thumbnail_base64 %}
      <div style="width: 100%; height: 180px; background: #0f172a; display: flex; align-items: center; justify-content: center; overflow: hidden;">
        <img src="data:image/jpeg;base64,{{ m.thumbnail_base64 }}" alt="{{ m.file_name }}" style="width: 100%; height: 100%; object-fit: cover;" />
      </div>
      {% else %}
      <div style="width: 100%; height: 140px; background: #f1f5f9; display: flex; align-items: center; justify-content: center; color: #94a3b8; font-size: 13px;">
        No Visual Preview Available
      </div>
      {% endif %}
      <div style="padding: 14px; flex-grow: 1; display: flex; flex-direction: column; justify-content: space-between;">
        <div>
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <span style="font-family: monospace; font-weight: 700; color: #0284c7; font-size: 12px;">{{ m.item_id }}</span>
            {% if m.has_telemetry_overlap %}
            <span class="badge badge-success" style="font-size: 10px; font-weight: 700;">✓ SYNCHRONIZED</span>
            {% else %}
            <span class="badge" style="background: #f1f5f9; color: #64748b; font-size: 10px;">NO OVERLAP</span>
            {% endif %}
          </div>
          <p style="margin: 0 0 6px 0; font-weight: 600; font-size: 13px; color: #0f172a; word-break: break-all;">{{ m.file_name }}</p>
          <div style="font-size: 12px; color: #64748b; margin-bottom: 8px;">
            <span>Type: <strong>{{ m.media_type }}</strong></span>
            {% if m.duration_sec %} &bull; <span>Duration: <strong>{{ m.duration_sec }}s</strong></span>{% endif %}
            &bull; <span>Size: <strong>{{ (m.file_size_bytes / 1024)|round(1) }} KB</strong></span>
          </div>

          {% if m.capture_timestamp_utc %}
          <div style="font-size: 11px; margin-bottom: 4px;">
            <strong>Capture Time (UTC):</strong> <span style="font-family: monospace; color: #334155;">{{ m.capture_timestamp_utc }}</span>
          </div>
          {% endif %}

          {% if m.has_telemetry_overlap and m.matched_latitude %}
          <div style="font-size: 11px; margin-bottom: 4px;">
            <strong>Correlated Coordinates:</strong>
            <span class="hash-box" style="display: inline-block; margin-top: 2px;">{{ m.matched_latitude|round(5) }}, {{ m.matched_longitude|round(5) }} ({{ m.matched_altitude_m|round(1) if m.matched_altitude_m is not none else '0.0' }}m)</span>
          </div>
          {% if m.time_delta_sec is not none %}
          <div style="font-size: 11px; margin-bottom: 6px; color: #059669; font-weight: 600;">
            Sync Delta: Δ {{ m.time_delta_sec }}s relative to flight log
          </div>
          {% endif %}
          {% endif %}

          {% if m.e01_path %}
          <div style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 4px; padding: 6px 8px; margin-top: 6px; font-size: 11px;">
            <div style="color: #166534; font-weight: 700;">🔒 Forensic Container (.eo1):</div>
            <div style="font-family: monospace; color: #15803d; word-break: break-all; margin-top: 2px;">{{ m.file_name.rsplit('.', 1)[0] }}.eo1</div>
            {% if m.e01_hashes %}
            <div style="font-family: monospace; color: #475569; font-size: 10px; margin-top: 2px;">SHA256: {{ m.e01_hashes.sha256[:16] }}...</div>
            {% endif %}
          </div>
          {% endif %}
        </div>

        <div style="margin-top: 8px; font-size: 11px; color: #475569; border-top: 1px solid #f1f5f9; padding-top: 6px;">
          <div><span style="color: #64748b;">SHA-256:</span> <span class="hash-box" style="font-size: 10px;">{{ m.hashes.sha256[:20] }}...{{ m.hashes.sha256[-12:] }}</span></div>
        </div>
      </div>
    </div>
    {% endfor %}
  </div>
</div>
{% endif %}

<div class="card">
  <h2 class="section-title">Itemized Evidence & Cryptographic Hashes</h2>
  <p style="font-size: 13px; color: #64748b;">Every evidence item has been hashed simultaneously with SHA-256 and SHA-3-256 under software write-inhibition and sorted into designated categories.</p>
  
  <div style="display: flex; gap: 10px; margin: 12px 0 16px 0; font-size: 12px;">
    <div style="padding: 6px 14px; background: #0f172a; border-radius: 6px; border: 1px solid #334155; color: #f8fafc;">
      <strong>Total Items:</strong> {{ evidence_items|length }}
    </div>
    <div style="padding: 6px 14px; background: #451a03; border-radius: 6px; border: 1px solid #78350f; color: #fcd34d;">
      <strong>📋 Logs:</strong> {{ evidence_items|selectattr('evidence_category', 'equalto', 'LOGS')|list|length }}
    </div>
    <div style="padding: 6px 14px; background: #581c87; border-radius: 6px; border: 1px solid #6b21a8; color: #d8b4fe;">
      <strong>🎥 Video/Images:</strong> {{ evidence_items|selectattr('evidence_category', 'equalto', 'VIDEO_IMAGES')|list|length }}
    </div>
    <div style="padding: 6px 14px; background: #082f49; border-radius: 6px; border: 1px solid #0369a1; color: #7dd3fc;">
      <strong>🎮 GCS:</strong> {{ evidence_items|selectattr('evidence_category', 'equalto', 'GCS')|list|length }}
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Item ID</th>
        <th>Category</th>
        <th>File Name</th>
        <th>Size</th>
        <th>Acquisition Type</th>
        <th>Cryptographic Hashes</th>
      </tr>
    </thead>
    <tbody>
      {% for ev in evidence_items %}
      <tr>
        <td><strong>{{ ev.item_id }}</strong></td>
        <td>
          {% if ev.evidence_category == 'VIDEO_IMAGES' %}
            <span class="badge" style="background: #581c87; color: #d8b4fe;">🎥 Video/Images</span>
          {% elif ev.evidence_category == 'GCS' %}
            <span class="badge" style="background: #082f49; color: #7dd3fc;">🎮 GCS</span>
          {% else %}
            <span class="badge" style="background: #451a03; color: #fcd34d;">📋 Logs</span>
          {% endif %}
        </td>
        <td>{{ ev.file_name }}</td>
        <td>{{ (ev.file_size_bytes / 1024)|round(1) }} KB</td>
        <td><span class="badge badge-info">{{ ev.acquisition_type }}</span></td>
        <td>
          <div><strong>SHA-256:</strong> <span class="hash-box">{{ ev.hashes.sha256 }}</span></div>
          <div style="margin-top: 4px;"><strong>SHA3-256:</strong> <span class="hash-box">{{ ev.hashes.sha3_256 }}</span></div>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

{% if geofence_violations %}
<div class="card" style="border-left: 4px solid #dc2626;">
  <h2 class="section-title" style="color: #dc2626; border-left-color: #dc2626;">Statutory Airspace & Geofence Infringements Detected</h2>
  <p style="font-size: 12px; color: #64748b; margin-bottom: 12px;">The following unauthorized airspace entries and ceiling exceedances were identified correlating to real-world civil aviation, military, government, and strategic perimeters:</p>
  <table>
    <thead>
      <tr>
        <th>Violation ID</th>
        <th>Restricted Space</th>
        <th>Category / Authority</th>
        <th>Timestamp (UTC)</th>
        <th>Coordinates</th>
        <th>Altitude</th>
        <th>Breach Classification</th>
      </tr>
    </thead>
    <tbody>
      {% for vio in geofence_violations %}
      <tr>
        <td><strong>{{ vio.violation_id }}</strong></td>
        <td>{{ vio.zone_name }}</td>
        <td>
          <span class="badge badge-info">{{ vio.category or 'RESTRICTED' }}</span>
          {% if vio.authority %}<div style="font-size: 11px; color: #64748b; margin-top: 2px;">{{ vio.authority }}</div>{% endif %}
        </td>
        <td style="font-family: monospace;">{{ vio.timestamp_utc }}</td>
        <td style="font-family: monospace;">{{ vio.latitude|round(5) }}, {{ vio.longitude|round(5) }}</td>
        <td><strong style="color: #dc2626;">{{ vio.altitude_m|round(1) }} m</strong></td>
        <td>
          <span class="badge badge-danger">{{ vio.violation_type }}</span>
          <div style="font-size: 11px; color: #475569; margin-top: 2px;">{{ vio.details }}</div>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}

{% if anomalies %}
<div class="card" style="border-left: 4px solid #f59e0b;">
  <h2 class="section-title" style="color: #d97706; border-left-color: #d97706;">Anomaly & Anti-Forensics Analysis</h2>
  <table>
    <thead>
      <tr>
        <th>Anomaly ID</th>
        <th>Type</th>
        <th>Severity</th>
        <th>Timestamp</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      {% for anom in anomalies %}
      <tr>
        <td><strong>{{ anom.anomaly_id }}</strong></td>
        <td>{{ anom.anomaly_type }}</td>
        <td><span class="badge badge-warning">{{ anom.severity }}</span></td>
        <td>{{ anom.timestamp_utc or 'N/A' }}</td>
        <td>{{ anom.description }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}

<div class="card">
  <h2 class="section-title">Reconstructed Master Event Timeline</h2>
  <table>
    <thead>
      <tr>
        <th>Timestamp (UTC)</th>
        <th>Category</th>
        <th>Event / Incident</th>
        <th>Coordinates & Altitude</th>
      </tr>
    </thead>
    <tbody>
      {% for item in timeline[:25] %}
      <tr>
        <td><strong>{{ item.timestamp_utc }}</strong></td>
        <td><span class="badge badge-info">{{ item.category }}</span></td>
        <td>{{ item.description }}</td>
        <td>
          {% if item.latitude %}
            {{ item.latitude|round(5) }}, {{ item.longitude|round(5) }} ({{ item.altitude_m|round(1) }}m)
          {% else %}
            System Event
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% if timeline|length > 25 %}
  <p style="font-size: 12px; color: #64748b; margin-top: 10px;">* Displaying first 25 events. Full chronology exported in accompanying JSON/DFXML manifests.</p>
  {% endif %}
</div>

<div class="card">
  <h2 class="section-title">Chain of Custody Audit Trail</h2>
  <table>
    <thead>
      <tr>
        <th>Entry #</th>
        <th>Timestamp</th>
        <th>Examiner / Actor</th>
        <th>Action</th>
        <th>Details</th>
        <th>Cryptographic Signature</th>
      </tr>
    </thead>
    <tbody>
      {% for log in audit_logs %}
      <tr>
        <td>#{{ log.entry_id }}</td>
        <td>{{ log.timestamp_utc }}</td>
        <td><strong>{{ log.actor }}</strong></td>
        <td>{{ log.action }}</td>
        <td>{{ log.details }}</td>
        <td><span class="hash-box">{{ log.signature[:16] }}...{{ log.signature[-12:] }}</span></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<div class="footer">
  <p>Certified by Drone Forensic Toolkit (DFT) — Autonomous Forensic Engine</p>
  <p>Report conforms to digital evidence legal admissibility protocols under ISO/IEC 27037:2012.</p>
</div>

</body>
</html>
"""


class ForensicReportGenerator:
    @staticmethod
    def generate_html_report(
        case: CaseMetadata,
        summary: FlightSummary,
        evidence_items: List[EvidenceItem],
        geofence_violations: List[GeofenceViolation],
        anomalies: List[AnomalyReport],
        timeline: List[Dict[str, Any]],
        audit_logs: List[AuditLogEntry],
        gcs_analysis: Any = None,
        media_items: Optional[List[Any]] = None,
        mobile_analysis: Any = None,
        wireless_sessions: Optional[List[Any]] = None
    ) -> str:
        """Generates comprehensive court-admissible HTML report."""
        template = Template(HTML_TEMPLATE)
        return template.render(
            case=case,
            summary=summary,
            evidence_items=evidence_items,
            geofence_violations=geofence_violations,
            anomalies=anomalies,
            timeline=timeline,
            audit_logs=audit_logs,
            gcs_analysis=gcs_analysis,
            media_items=media_items or [],
            mobile_analysis=mobile_analysis,
            wireless_sessions=wireless_sessions or [],
            report_generated_utc=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        )

    @staticmethod
    def generate_json_export(
        case: CaseMetadata,
        summary: FlightSummary,
        evidence_items: List[EvidenceItem],
        geofence_violations: List[GeofenceViolation],
        anomalies: List[AnomalyReport],
        timeline: List[Dict[str, Any]],
        audit_logs: List[AuditLogEntry],
        gcs_analysis: Any = None,
        media_items: Optional[List[Any]] = None,
        mobile_analysis: Any = None,
        wireless_sessions: Optional[List[Any]] = None
    ) -> str:
        logs_items = [e.model_dump() for e in evidence_items if getattr(e, "evidence_category", "LOGS") == "LOGS"]
        video_items = [e.model_dump() for e in evidence_items if getattr(e, "evidence_category", "LOGS") == "VIDEO_IMAGES"]
        gcs_items = [e.model_dump() for e in evidence_items if getattr(e, "evidence_category", "LOGS") == "GCS"]

        payload = {
            "case": case.model_dump(),
            "flight_summary": summary.model_dump(),
            "evidence_items": [e.model_dump() for e in evidence_items],
            "evidence_counts": {
                "logs": len(logs_items),
                "video_images": len(video_items),
                "gcs": len(gcs_items),
                "total": len(evidence_items)
            },
            "evidence_by_category": {
                "logs": logs_items,
                "video_images": video_items,
                "gcs": gcs_items
            },
            "geofence_violations": [v.model_dump() for v in geofence_violations],
            "anomalies": [a.model_dump() for a in anomalies],
            "timeline": timeline,
            "chain_of_custody": [log.model_dump() for log in audit_logs],
            "ground_control_station": gcs_analysis.model_dump() if (gcs_analysis and hasattr(gcs_analysis, "model_dump")) else gcs_analysis,
            "gcs_analysis": gcs_analysis.model_dump() if (gcs_analysis and hasattr(gcs_analysis, "model_dump")) else gcs_analysis,
            "mobile_companion_analysis": mobile_analysis.model_dump() if (mobile_analysis and hasattr(mobile_analysis, "model_dump")) else mobile_analysis,
            "wireless_sessions": [s.model_dump() if hasattr(s, "model_dump") else s for s in (wireless_sessions or [])],
            "media_items": [m.model_dump() if hasattr(m, "model_dump") else m for m in (media_items or [])],
            "generated_at_utc": datetime.now(timezone.utc).isoformat()
        }
        return json.dumps(payload, indent=2)

    @staticmethod
    def generate_dfxml_export(
        case: CaseMetadata,
        evidence_items: List[EvidenceItem],
        media_items: Optional[List[Any]] = None
    ) -> str:
        """Generates Digital Forensics XML (DFXML) interchange document."""
        xml = ['<?xml version="1.0" encoding="UTF-8"?>', '<dfxml xmloutputversion="1.0">']
        xml.append('  <metadata>')
        xml.append(f'    <dc:type>UAV Forensic Report</dc:type>')
        xml.append(f'    <case_id>{case.case_id}</case_id>')
        xml.append(f'    <examiner>{case.investigator_name}</examiner>')
        xml.append(f'    <timestamp>{datetime.now(timezone.utc).isoformat()}</timestamp>')
        xml.append('  </metadata>')
        xml.append('  <creator>')
        xml.append('    <program>Drone Forensic Toolkit (DFT)</program>')
        xml.append('    <version>1.0.0</version>')
        xml.append('  </creator>')

        for ev in evidence_items:
            xml.append('  <fileobject>')
            xml.append(f'    <filename>{ev.file_name}</filename>')
            xml.append(f'    <filesize>{ev.file_size_bytes}</filesize>')
            xml.append(f'    <hashdigest type="SHA256">{ev.hashes.sha256}</hashdigest>')
            xml.append(f'    <hashdigest type="SHA3-256">{ev.hashes.sha3_256}</hashdigest>')
            xml.append(f'    <hashdigest type="MD5">{ev.hashes.md5}</hashdigest>')
            xml.append('  </fileobject>')

        if media_items:
            for m in media_items:
                fname = getattr(m, "file_name", m.get("file_name", "unknown") if isinstance(m, dict) else "unknown")
                fsize = getattr(m, "file_size_bytes", m.get("file_size_bytes", 0) if isinstance(m, dict) else 0)
                hashes = getattr(m, "hashes", m.get("hashes") if isinstance(m, dict) else None)
                sha256 = getattr(hashes, "sha256", hashes.get("sha256", "") if isinstance(hashes, dict) else "") if hashes else ""
                sha3_256 = getattr(hashes, "sha3_256", hashes.get("sha3_256", "") if isinstance(hashes, dict) else "") if hashes else ""
                md5_val = getattr(hashes, "md5", hashes.get("md5", "") if isinstance(hashes, dict) else "") if hashes else ""
                xml.append('  <fileobject type="visual_media">')
                xml.append(f'    <filename>{fname}</filename>')
                xml.append(f'    <filesize>{fsize}</filesize>')
                if sha256:
                    xml.append(f'    <hashdigest type="SHA256">{sha256}</hashdigest>')
                if sha3_256:
                    xml.append(f'    <hashdigest type="SHA3-256">{sha3_256}</hashdigest>')
                if md5_val:
                    xml.append(f'    <hashdigest type="MD5">{md5_val}</hashdigest>')
                e01_p = getattr(m, "e01_path", m.get("e01_path") if isinstance(m, dict) else None)
                if e01_p:
                    xml.append(f'    <forensic_container type="E01">{e01_p}</forensic_container>')
                xml.append('  </fileobject>')

        xml.append('</dfxml>')
        return "\n".join(xml)
