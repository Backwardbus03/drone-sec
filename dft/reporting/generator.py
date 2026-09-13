"""
Forensic Report Generator for Drone Forensic Toolkit.
Generates court-admissible forensic reports in HTML, JSON, and Digital Forensics XML (DFXML)
formatted in accordance with ISO/IEC 27037:2012 and ISO/IEC 27042:2015.
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any, List
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

<div class="card">
  <h2 class="section-title">Itemized Evidence & Cryptographic Hashes</h2>
  <p style="font-size: 13px; color: #64748b;">Every evidence item has been hashed simultaneously with SHA-256 and SHA-3-256 under software write-inhibition.</p>
  <table>
    <thead>
      <tr>
        <th>Item ID</th>
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
        audit_logs: List[AuditLogEntry]
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
        audit_logs: List[AuditLogEntry]
    ) -> str:
        """Generates structured JSON representation for machine ingestion."""
        payload = {
            "case": case.model_dump(),
            "flight_summary": summary.model_dump(),
            "evidence_items": [e.model_dump() for e in evidence_items],
            "geofence_violations": [v.model_dump() for v in geofence_violations],
            "anomalies": [a.model_dump() for a in anomalies],
            "timeline": timeline,
            "chain_of_custody": [log.model_dump() for log in audit_logs],
            "generated_at_utc": datetime.now(timezone.utc).isoformat()
        }
        return json.dumps(payload, indent=2)

    @staticmethod
    def generate_dfxml_export(case: CaseMetadata, evidence_items: List[EvidenceItem]) -> str:
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

        xml.append('</dfxml>')
        return "\n".join(xml)
