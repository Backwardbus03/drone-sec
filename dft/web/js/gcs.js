/**
 * Drone Forensic Toolkit (DFT) — Ground Control Station (GCS) & Operator Module
 * Handles GCS mission plan extraction, operator launch point geolocation,
 * planned waypoint parsing, and interactive mission compliance mapping.
 */

let gcsMap = null;
let gcsMapLayers = null;
let cachedGcsData = null;

function initGcsMap() {
  if (!gcsMap) {
    const el = document.getElementById('gcsMap');
    if (!el) return;
    gcsMap = L.map('gcsMap').setView([19.1334, 72.9133], 14);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '&copy; OpenStreetMap contributors',
      maxZoom: 19
    }).addTo(gcsMap);
    gcsMapLayers = L.layerGroup().addTo(gcsMap);
  }
}

async function loadGcsData() {
  if (!activeCaseId) return;
  try {
    const res = await fetch(`/api/cases/${activeCaseId}/gcs`);
    if (!res.ok) {
      cachedGcsData = null;
      renderGcsMap();
      return;
    }
    const data = await res.json();
    cachedGcsData = data;

    const gcsName = (data.detected_gcs && data.detected_gcs !== 'NONE') ? data.detected_gcs : (data.gcs_software || 'None');
    const targetFc = (data.associated_fc && data.associated_fc !== 'NONE') ? data.associated_fc : '';
    const op = (data.operator_locations && data.operator_locations.length > 0) ? data.operator_locations[0] : (data.operator_location || null);
    const plan = (data.mission_plans && data.mission_plans.length > 0) ? data.mission_plans[0] : (data.mission_plan || null);
    const tc = data.mission_comparison || data.trajectory_comparison || null;

    // 1. Stats Cards
    const gcsPlat = document.getElementById('gcsStatPlatform');
    if (gcsPlat) gcsPlat.textContent = gcsName;

    const gcsFc = document.getElementById('gcsStatFC');
    if (gcsFc) {
      if (targetFc) {
        gcsFc.textContent = `FC: ${targetFc}`;
      } else {
        let fc = 'FC: General UAV';
        const s = (gcsName || '').toLowerCase();
        if (s.includes('mission planner') || s.includes('mavproxy')) fc = 'FC: ArduPilot (Pixhawk/Cube)';
        else if (s.includes('qgroundcontrol')) fc = 'FC: PX4 / ArduPilot';
        else if (s.includes('dji')) fc = 'FC: DJI Enterprise / Consumer';
        else if (s.includes('inav') || s.includes('mwp')) fc = 'FC: Betaflight / iNav FPV';
        else if (s.includes('parrot')) fc = 'FC: Parrot FreeFlight';
        gcsFc.textContent = fc;
      }
    }

    const gcsOp = document.getElementById('gcsStatOperator');
    const gcsSrc = document.getElementById('gcsStatOpSource');
    if (op) {
      if (gcsOp) gcsOp.textContent = `${op.latitude.toFixed(6)}, ${op.longitude.toFixed(6)}`;
      if (gcsSrc) gcsSrc.textContent = `Alt: ${op.altitude_m !== null && op.altitude_m !== undefined ? op.altitude_m : 0}m (${op.source || 'Header'})`;
    } else {
      if (gcsOp) gcsOp.textContent = 'Not Identified';
      if (gcsSrc) gcsSrc.textContent = 'Source: --';
    }

    const gcsWp = document.getElementById('gcsStatWaypoints');
    const gcsDist = document.getElementById('gcsStatPlanDist');
    if (plan) {
      const wpCount = plan.waypoints ? plan.waypoints.length : (plan.waypoint_count || 0);
      if (gcsWp) gcsWp.textContent = wpCount;
      if (gcsDist) gcsDist.textContent = `Planned Dist: ${plan.total_planned_distance_m} m`;
    } else {
      if (gcsWp) gcsWp.textContent = '0';
      if (gcsDist) gcsDist.textContent = 'Planned Dist: 0 m';
    }

    const gcsAdh = document.getElementById('gcsStatAdherence');
    const gcsRch = document.getElementById('gcsStatReached');
    if (tc) {
      const score = tc.compliance_score_pct !== undefined ? tc.compliance_score_pct : tc.adherence_score_pct;
      if (gcsAdh) gcsAdh.textContent = `${score}%`;
      if (gcsRch) gcsRch.textContent = `${tc.waypoints_reached} / ${tc.waypoints_total} reached (Mean Dev: ${tc.mean_deviation_meters}m)`;
    } else {
      if (gcsAdh) gcsAdh.textContent = '-- %';
      const count = plan && plan.waypoints ? plan.waypoints.length : 0;
      if (gcsRch) gcsRch.textContent = count > 0 ? `${count} planned (No telemetry overlay)` : '0 / 0 reached';
    }

    // 2. Waypoints Table
    const tbody = document.getElementById('gcsWaypointsTableBody');
    const countBadge = document.getElementById('gcsWaypointCountBadge');
    if (plan && plan.waypoints && plan.waypoints.length > 0) {
      const wps = plan.waypoints;
      if (countBadge) countBadge.textContent = `${wps.length} waypoints`;
      if (tbody) {
        tbody.innerHTML = '';
        const reachedCount = tc ? tc.waypoints_reached : null;

        wps.forEach(wp => {
          const tr = document.createElement('tr');
          const wpIdx = wp.index !== undefined ? wp.index : wp.sequence;
          const wpCmd = wp.command || wp.action || 'WAYPOINT';
          let statusBadge = '<span class="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px] font-mono">PLANNED</span>';
          if (reachedCount !== null) {
            if (wpIdx <= reachedCount) {
              statusBadge = '<span class="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold text-[10px] font-mono">✓ REACHED</span>';
            } else {
              statusBadge = '<span class="px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-800 font-bold text-[10px] font-mono">DEVIATED</span>';
            }
          }

          const spdText = (wp.speed_mps !== null && wp.speed_mps !== undefined) ? `${wp.speed_mps.toFixed(1)} m/s` : '--';
          const holdText = wp.param1 ? `${wp.param1}s` : (wp.hold_time_sec ? `${wp.hold_time_sec}s` : '0s');

          tr.innerHTML = `
            <td class="p-2.5 font-mono text-cyan-400 font-bold text-center">#${wpIdx}</td>
            <td class="p-2.5 font-medium text-white">${wpCmd}</td>
            <td class="p-2.5 font-mono text-slate-300">${wp.latitude.toFixed(6)}, ${wp.longitude.toFixed(6)}</td>
            <td class="p-2.5 font-mono text-slate-200">${wp.altitude_m.toFixed(1)} m</td>
            <td class="p-2.5 font-mono text-slate-300">${spdText}</td>
            <td class="p-2.5 font-mono text-slate-400">${holdText}</td>
            <td class="p-2.5">${statusBadge}</td>
          `;
          tbody.appendChild(tr);
        });
      }
    } else {
      if (countBadge) countBadge.textContent = '0 waypoints';
      if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="p-4 text-center text-slate-500">No GCS mission plan loaded for this case.</td></tr>';
    }

    renderGcsMap();
  } catch (e) {
    console.error('Error loading GCS data:', e);
  }
}

function renderGcsMap() {
  initGcsMap();
  if (!gcsMap || !gcsMapLayers) return;
  gcsMapLayers.clearLayers();

  let hasBounds = false;
  let bounds = L.latLngBounds();

  // 1. Overlay Flown Telemetry
  if (activeGeoJson && activeGeoJson.features && activeGeoJson.features.length > 0) {
    const flownLayer = L.geoJSON(activeGeoJson, {
      style: { color: '#0284c7', weight: 4, opacity: 0.85 },
      pointToLayer: function(feature, latlng) {
        return L.circleMarker(latlng, { radius: 4, fillColor: '#38bdf8', color: '#fff', weight: 1, fillOpacity: 0.9 });
      }
    });
    flownLayer.addTo(gcsMapLayers);
    bounds.extend(flownLayer.getBounds());
    hasBounds = true;
  }

  const plan = cachedGcsData ? ((cachedGcsData.mission_plans && cachedGcsData.mission_plans.length > 0) ? cachedGcsData.mission_plans[0] : (cachedGcsData.mission_plan || null)) : null;
  const op = cachedGcsData ? ((cachedGcsData.operator_locations && cachedGcsData.operator_locations.length > 0) ? cachedGcsData.operator_locations[0] : (cachedGcsData.operator_location || null)) : null;

  // 2. Overlay Planned Waypoints
  if (plan && plan.waypoints && plan.waypoints.length > 0) {
    const wps = plan.waypoints;
    const pts = wps.map(w => [w.latitude, w.longitude]);

    L.polyline(pts, {
      color: '#06b6d4',
      weight: 3,
      dashArray: '6, 8',
      opacity: 0.9
    }).addTo(gcsMapLayers);

    wps.forEach(wp => {
      const wpIdx = wp.index !== undefined ? wp.index : wp.sequence;
      const wpCmd = wp.command || wp.action || 'NAV';
      const wpIcon = L.divIcon({
        className: 'custom-wp-pin',
        html: `<div style="background:#06b6d4; color:#020617; font-weight:bold; font-size:10px; border-radius:9999px; width:20px; height:20px; display:flex; align-items:center; justify-content:center; border:1.5px solid #ffffff; box-shadow:0 2px 4px rgba(0,0,0,0.5);">${wpIdx}</div>`,
        iconSize: [20, 20],
        iconAnchor: [10, 10]
      });

      const m = L.marker([wp.latitude, wp.longitude], { icon: wpIcon })
        .bindPopup(`<strong>Waypoint #${wpIdx}</strong><br/>Command: ${wpCmd}<br/>Coords: ${wp.latitude.toFixed(6)}, ${wp.longitude.toFixed(6)}<br/>Planned Alt: ${wp.altitude_m}m`);
      m.addTo(gcsMapLayers);
      bounds.extend([wp.latitude, wp.longitude]);
      hasBounds = true;
    });
  }

  // 3. Overlay Operator / GCS Launch Marker
  if (op) {
    const opIcon = L.divIcon({
      className: 'custom-op-pin',
      html: `<div style="background:#10b981; color:#ffffff; font-size:14px; border-radius:9999px; width:30px; height:30px; display:flex; align-items:center; justify-content:center; border:2px solid #ffffff; box-shadow:0 0 12px rgba(16,185,129,0.8);">🎮</div>`,
      iconSize: [30, 30],
      iconAnchor: [15, 15]
    });

    const m = L.marker([op.latitude, op.longitude], { icon: opIcon })
      .bindPopup(`<strong>🎯 Operator / Ground Control Station</strong><br/>Coords: ${op.latitude.toFixed(6)}, ${op.longitude.toFixed(6)}<br/>Altitude: ${op.altitude_m !== null && op.altitude_m !== undefined ? op.altitude_m : 0}m<br/>Source: ${op.source || 'GCS Header'}`);
    m.addTo(gcsMapLayers);
    bounds.extend([op.latitude, op.longitude]);
    hasBounds = true;
  }

  if (hasBounds) {
    gcsMap.fitBounds(bounds, { padding: [40, 40] });
  }
}

async function uploadGcsArtifact() {
  if (!activeCaseId) {
    alert('Please select or create an active case first.');
    return;
  }
  const input = document.getElementById('gcsFileInput');
  if (!input.files || input.files.length === 0) {
    alert('Please choose a GCS evidence file to upload.');
    return;
  }
  const file = input.files[0];
  const btn = document.getElementById('uploadGcsBtn');
  const spinner = document.getElementById('uploadGcsBtnSpinner');
  const alertBox = document.getElementById('gcsUploadAlert');

  btn.disabled = true;
  if (spinner) spinner.classList.remove('hidden');
  alertBox.className = 'p-3 rounded-lg text-xs bg-sky-950/80 border border-sky-800 text-sky-200 block';
  alertBox.innerHTML = `Ingesting GCS artifact <strong>${file.name}</strong>...`;

  try {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('acquisition_type', 'LOGICAL_EXTRACT');
    formData.append('actor', 'GCS Forensic Analyst');

    const res = await fetch(`/api/cases/${activeCaseId}/ingest`, {
      method: 'POST',
      body: formData
    });

    if (res.ok) {
      const data = await res.json();
      const plat = (data.platform_detected || data.platform || 'UNKNOWN').toUpperCase();
      alertBox.className = 'p-3 rounded-lg text-xs bg-emerald-950/80 border border-emerald-800 text-emerald-200 block';
      alertBox.innerHTML = `✓ <strong>GCS Evidence Ingested!</strong> File <code>${file.name}</code> processed. Platform: <strong>${plat}</strong>. Cryptographic hashes logged to Chain of Custody.`;
      input.value = '';
      await refreshCaseData();

      // Hook into Guided Ingestion Workflow if active
      if (typeof onGcsIngested === 'function') {
        onGcsIngested();
      }
    } else {
      const err = await res.json();
      alertBox.className = 'p-3 rounded-lg text-xs bg-red-950/80 border border-red-800 text-red-200 block';
      alertBox.innerHTML = `❌ Error ingesting file: ${err.detail || 'Unknown error'}`;
    }
  } catch (e) {
    alertBox.className = 'p-3 rounded-lg text-xs bg-red-950/80 border border-red-800 text-red-200 block';
    alertBox.innerHTML = `❌ Network or processing error: ${e.message}`;
  } finally {
    btn.disabled = false;
    if (spinner) spinner.classList.add('hidden');
  }
}

async function loadSampleGcs(sampleFile) {
  if (!activeCaseId) {
    alert('Please select or create an active case first.');
    return;
  }
  const alertBox = document.getElementById('gcsUploadAlert');
  alertBox.className = 'p-3 rounded-lg text-xs bg-sky-950/80 border border-sky-800 text-sky-200 block';
  alertBox.innerHTML = `Fetching sample GCS file <strong>${sampleFile}</strong> and parsing mission trajectory...`;

  try {
    const blobRes = await fetch(`/samples/${sampleFile}`);
    if (!blobRes.ok) {
      alert('Could not locate sample file: ' + sampleFile);
      return;
    }
    const blob = await blobRes.blob();
    const formData = new FormData();
    formData.append('file', blob, sampleFile);
    formData.append('acquisition_type', 'LOGICAL_EXTRACT');
    formData.append('actor', 'GCS Benchmark Examiner');

    const res = await fetch(`/api/cases/${activeCaseId}/ingest`, {
      method: 'POST',
      body: formData
    });

    if (res.ok) {
      const data = await res.json();
      const plat = (data.platform_detected || data.platform || 'GCS').toUpperCase();
      alertBox.className = 'p-3 rounded-lg text-xs bg-emerald-950/80 border border-emerald-800 text-emerald-200 block';
      alertBox.innerHTML = `✓ <strong>Sample GCS Evidence Ingested!</strong> File <code>${sampleFile}</code> processed. Platform: <strong>${plat}</strong>. Cryptographic hashes logged to Chain of Custody.`;
      await refreshCaseData();

      // Hook into Guided Ingestion Workflow if active
      if (typeof onGcsIngested === 'function') {
        onGcsIngested();
      }
    } else {
      const err = await res.json();
      alertBox.className = 'p-3 rounded-lg text-xs bg-red-950/80 border border-red-800 text-red-200 block';
      alertBox.innerHTML = `❌ Error ingesting sample file: ${err.detail || 'Unknown error'}`;
    }
  } catch (e) {
    alertBox.className = 'p-3 rounded-lg text-xs bg-red-950/80 border border-red-800 text-red-200 block';
    alertBox.innerHTML = `❌ Network or processing error: ${e.message}`;
  }
}
